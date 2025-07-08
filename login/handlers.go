package login

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"test-cv/dbUtils"
	"test-cv/models"
	"test-cv/utils"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

func LoginHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		log.Debug().Msgf("Request body: %v\n", r.Body)

		vars := mux.Vars(r)
		userID := vars["guid"]

		checkUUID, err := dbUtils.CheckGUID(db, userID)
		if err != nil {
			err := fmt.Sprintf("Error occured while checking existing uuid in db %v", err)
			log.Error().Msgf(err)
			http.Error(w, err, http.StatusBadRequest)
		}
		//use go-playground/validation/v10
		var u models.User
		json.NewDecoder(r.Body).Decode(&u)

		if checkUUID == true {
			var (
				resp models.UpdateTokensPairResponse
			)

			accessToken, err := generateToken(u.Username, userID)
			if err != nil {
				log.Error().Msgf(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			cookie := http.Cookie{
				Name:     "accessToken",
				Value:    accessToken,
				Path:     "/",
				MaxAge:   1800,
				HttpOnly: true,
				//Работает только с https и на localhost
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			}
			http.SetCookie(w, &cookie)
			log.Debug().Msgf("cookie set! %s", &cookie)
			//utils.SetCookieHandler("accessToken", accessToken, 1800)

			//Как хранить в bcrypt в базе? Теряется смысл refresh токена. cf.(https://gist.github.com/zmts/802dc9c3510d79fd40f9dc38a12bccfc?permalink_comment_id=4195129)
			//bcrypt - односторонний алгоритм хеширования, соответственно надо хранить нехешированную копию в куках, а если нехешированная копия есть в куках, то не имеет смысла хранить ее в базе
			//https://stackoverflow.com/questions/18084595/how-to-decrypt-hash-stored-by-bcrypt
			//Буду использовать AES.
			refreshToken, err := generateToken(u.Username, userID)
			if err != nil {
				log.Error().Msgf(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)

				return
			}
			encryptedRefreshToken := utils.EncryptAES(refreshToken)
			err = dbUtils.UpdateRefreshToken(db, userID, encryptedRefreshToken)
			if err != nil {
				log.Error().Msgf(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)

				return
			}

			//Получаем User-Agent пользователя
			dbUtils.UpdateIPandUA(db, userID, r.RemoteAddr, r.UserAgent())
			log.Debug().Msgf(accessToken, "\n", encryptedRefreshToken)
			resp.AccessToken = accessToken
			resp.RefreshToken = encryptedRefreshToken

			res, err := json.Marshal(resp)
			if err != nil {
				log.Error().Msgf("client: could not read response body: %s\n", err)
				http.Error(w, "Unable to read response", http.StatusInternalServerError)

				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(res)
		} else {
			errLog := fmt.Sprintf("Invalid credentials passed for %s", u.Username)
			log.Error().Msgf(errLog)
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, errLog, http.StatusUnauthorized)

			return
		}
	}
}

func RefreshHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			u    models.User
			resp models.UpdateTokensPairResponse
		)

		cookie, err := r.Cookie("accessToken")
		if err != nil {
			switch {
			case errors.Is(err, http.ErrNoCookie):
				http.Error(w, "cookie not found", http.StatusBadRequest)
			default:
				log.Error().Msgf(err.Error())
				http.Error(w, "server error", http.StatusInternalServerError)
			}
			return
		}
		accessToken := cookie.Value
		guid, err := parseGUIDfromJWT(accessToken)
		if err != nil {
			log.Error().Msgf("Error occured while parsing JWT token %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}
		refreshToken, err := dbUtils.GetRefreshTokenByGUID(db, guid)
		if err != nil {
			log.Error().Msgf("Error occured while getting refreshToken from db %v", refreshToken)
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}
		refreshToken = utils.DecryptAES(refreshToken)

		guidFromRT, err := parseGUIDfromJWT(refreshToken)
		if err != nil {
			log.Error().Msgf("Error occured while parsing GUID %v", refreshToken)
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		currIP := r.RemoteAddr
		currUserAgent := r.UserAgent()
		ip, userAgent := dbUtils.GetIPandUA(db, guid)
		//Проверка на подмену куки(подмена access токена) и на соответствие юзер агента
		if guidFromRT == guid && currUserAgent == userAgent {
			if currIP != ip {
				//отправляем запрос на вебсокет
				http.NewRequest("POST", "/websocket", strings.NewReader(currIP))
			}
			//Удаляем куку, чтобы избежать кражи токена в момент замены
			utils.SetCookieHandler("accessToken", "", -1)
			accessToken, err := generateToken(u.Username, guid)
			if err != nil {
				log.Error().Msgf(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)

				return
			}
			utils.SetCookieHandler("accessToken", accessToken, 1800)

			//Получаем новый рефреш токен
			refreshToken, err := generateToken(u.Username, guid)
			if err != nil {
				log.Error().Msgf(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)

				return
			}
			encryptedRefreshToken := utils.EncryptAES(refreshToken)
			err = dbUtils.UpdateRefreshToken(db, guid, encryptedRefreshToken)
			if err != nil {
				errLog := fmt.Sprintf("Error occured while processing encrypted token and pushing it to db %v", err)
				log.Error().Msgf(errLog)
				http.Error(w, errLog, http.StatusInternalServerError)

				return
			}

			log.Debug().Msgf("Tokens has been updated %s: %s", accessToken, "\n")

			resp.AccessToken = accessToken
			resp.RefreshToken = encryptedRefreshToken

			res, err := json.Marshal(resp)
			if err != nil {
				log.Error().Msgf("client: could not read response body: %s\n", err)
				http.Error(w, "Unable to read response", http.StatusInternalServerError)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(res)
		}
	}
}

// По хорошему JWT-токен должен передаваться в authorization хедере Bearer строкой
func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	var (
		resp models.CurrentGuidResponse
	)

	cookie, err := r.Cookie("accessToken")
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			log.Error().Msgf(err.Error())
			http.Error(w, "cookie not found", http.StatusBadRequest)

			return
		default:
			log.Error().Msgf(err.Error())
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}
	tokenString := cookie.Value
	if tokenString == "" {
		log.Error().Msgf("Missing authorization cookie")
		http.Error(w, "Missing authorization cookie", http.StatusUnauthorized)

		return
	}

	err = verifyToken(tokenString)
	if err != nil {
		log.Error().Msgf("Invalid token")
		http.Error(w, "Invalid token", http.StatusUnauthorized)

		return
	}
	guid, err := parseGUIDfromJWT(tokenString)
	if err != nil {
		log.Error().Msgf("error while parse GUID from JWT %v", err)
		http.Error(w, "Error parsing guid from jwt", http.StatusInternalServerError)

		return
	}

	log.Debug().Msgf("received guid: %s", guid)

	resp.GUID = guid

	res, err := json.Marshal(resp)
	if err != nil {
		log.Error().Msgf("client: could not read response body: %s\n", err)
		http.Error(w, "Unable to read response", http.StatusInternalServerError)

		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(res)
}

func LogoutHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accessCookie, err := r.Cookie("accessToken")
		if err != nil {
			switch {
			case errors.Is(err, http.ErrNoCookie):
				log.Error().Msgf(err.Error())
				http.Error(w, "cookie not found", http.StatusBadRequest)

				return
			default:
				log.Error().Msgf(err.Error())
				http.Error(w, "server error", http.StatusInternalServerError)
			}
			return
		}
		accessToken := accessCookie.Value
		guid, err := parseGUIDfromJWT(accessToken)
		if err != nil {
			log.Error().Msgf("Error occured while parsing JWT token %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}
		dbUtils.UpdateRefreshToken(db, guid, "NULL")
		cookie := http.Cookie{
			Name:     "accessToken",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			//Работает только с https и на localhost
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, &cookie)
		log.Debug().Msg(cookie.Expires.String())

		w.Header().Set("Content-Type", "application/json")
	}
}
