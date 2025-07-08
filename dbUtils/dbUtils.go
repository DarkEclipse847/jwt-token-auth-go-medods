package dbUtils

import (
	"database/sql"

	"github.com/rs/zerolog/log"

	_ "github.com/lib/pq"
)

func CreateTable(db *sql.DB) error {
	_, err := db.Exec("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, guid VARCHAR(36) UNIQUE, username TEXT, password TEXT, refreshToken TEXT, userAgent TEXT, ip TEXT)")
	if err != nil {
		log.Error().Msgf("Error occured while creating table %v", err)
		return err
	}
	return nil
}

func DropTable(db *sql.DB) error {
	_, err := db.Exec("DROP TABLE users")
	if err != nil {
		log.Error().Msgf("Error occured while creating table %v", err)
		return err
	}
	return nil
}

func InsertTestUser(db *sql.DB) error {
	// Вставляем тестовое значение
	// ПАРОЛЬ НАДО ЗАХЕШИРОВАТЬ С СОЛЬЮ/ПЕРЦЕМ, ХРАНИТЬ ПАРОЛИ ТАК НЕЛЬЗЯ!!
	_, err := db.Exec("INSERT INTO users (guid, username, password, refreshToken, userAgent, ip) VALUES('xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx', 'John Doe', '123456', 'token', NULL, NULL)")
	if err != nil {
		log.Error().Msgf("Error occured while inserting test value %v", err)
		return err
	}
	return nil
}

func CheckGUID(db *sql.DB, guid string) (bool, error) {
	var exists bool
	// Ограничиваем запрос (LIMIT 1) чтобы поиск выполнялся быстрее
	err := db.QueryRow("SELECT exists(SELECT 1 FROM users WHERE guid = $1 LIMIT 1)", guid).Scan(&exists)
	if err != nil {
		log.Error().Msgf("Error occured while check guid existence %v", err)
		return false, err
	}
	return exists, err
}

func UpdateRefreshToken(db *sql.DB, guid string, token string) error {
	_, err := db.Exec("UPDATE users SET refreshToken = $1 WHERE guid = $2", token, guid)
	if err != nil {
		log.Error().Msgf("Error occured while updating refreshToken %v", err)
		return err
	}
	return nil
}

func UpdateIPandUA(db *sql.DB, guid string, ip string, userAgent string) error {
	_, err := db.Exec("UPDATE users SET ip = $1, userAgent = $2 WHERE guid = $3", ip, userAgent, guid)
	if err != nil {
		log.Error().Msgf("Error occured while updating IP and user-agent %v", err)
		return err
	}
	return nil
}

func GetIPandUA(db *sql.DB, guid string) (string, string) {
	var ip, userAgent string
	err := db.QueryRow("SELECT ip, userAgent FROM users WHERE guid = $1 LIMIT 1", guid).Scan(&ip, &userAgent)
	if err != nil {
		log.Error().Msgf("Error occured while getting User-Agent and ip %v", err)
		return "", ""
	}
	return ip, userAgent
}

func GetRefreshTokenByGUID(db *sql.DB, guid string) (string, error) {
	var refreshToken string
	err := db.QueryRow("SELECT refreshToken FROM users WHERE guid = $1 LIMIT 1", guid).Scan(&refreshToken)
	if err != nil {
		log.Error().Msgf("Error occured while getting refresh token bu guid %v", err)
		return refreshToken, err
	}
	return refreshToken, err
}
