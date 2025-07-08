package utils

import (
	"net/http"

	"github.com/rs/zerolog/log"
)

// DEPRECATED удалить!!
func SetCookieHandler(cookieName string, cookieValue string, cookieAge int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie := http.Cookie{
			Name:     cookieName,
			Value:    cookieValue,
			Path:     "/",
			MaxAge:   cookieAge,
			HttpOnly: true,
			//Работает только с https и на localhost
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, &cookie)
		log.Debug().Msgf("cookie set! %s", &cookie)
	}
}
