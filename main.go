// 1. Создать access токен с информацией о GUID
// 2. Создать refresh токен, передать пару токенов при GET запросе
// 3. Создать API endpoint для получения пары ключей, создать prtected route с доступом по jwt access ключу
// 4. Установить связь с db, создать тестовый инстанс с GUID, username, passwd, и первичным ключом по id
// 5.

package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	dbUtils "test-cv/dbUtils"
	"test-cv/login"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// GUID указывается в параметре запроса, но мы получаем его под защищенным роутом?
func main() {

	//init logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	//2 use go-playground/validation/v10

	//db init
	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal().Msgf(err.Error())
	}
	defer db.Close()

	err = dbUtils.DropTable(db)
	if err != nil {
		log.Fatal().Msgf(err.Error())

	}

	//init db connection
	err = dbUtils.CreateTable(db)
	if err != nil {
		log.Fatal().Msgf(err.Error())

	}
	err = dbUtils.InsertTestUser(db)
	if err != nil {
		log.Fatal().Msgf(err.Error())
	}

	router := mux.NewRouter()

	authRouter := router.Methods(http.MethodPost, http.MethodGet).Subrouter()

	authRouter.HandleFunc("/login/{guid}", login.LoginHandler(db)).Methods("POST") // Получаем access и refresh токены
	authRouter.HandleFunc("/refresh", login.RefreshHandler(db)).Methods("GET")     // Обновляем пару jwt-токенов
	authRouter.HandleFunc("/guid", login.ProtectedHandler).Methods("GET")          // Получаем GUID
	authRouter.HandleFunc("/logout", login.LogoutHandler(db)).Methods("POST")      // Разлогиниваемся (ограничение доступа к  /guid и /refresh)

	probesRouter := router.Methods(http.MethodGet).Subrouter()
	probesRouter.HandleFunc("/probes/readiness",
		func(rw http.ResponseWriter, r *http.Request) {
			_, err := rw.Write([]byte("OK"))
			if err != nil {
				log.Error().Msgf("Error while writing the data to an HTTP reply with err=%s", err)
				return
			}
		})

	probesRouter.HandleFunc("/probes/liveness", func(rw http.ResponseWriter, r *http.Request) {

		//check if we can access DB
		connStr := os.Getenv("DATABASE_URL")

		db, err := sql.Open("postgres", connStr)
		log.Info().Msgf("Successful db connect: %v", db)

		if err != nil {
			log.Error().Msgf("Error while connection to DB with err=%s", err)
			return
		}
	})

	port := os.Getenv("APPLICATION_PORT")
	if len(port) == 0 {
		log.Fatal().Msgf("APPLICATION_PORT env doesnot not set")
	}
	srvPort, err := strconv.Atoi(port)
	if err != nil {
		log.Fatal().Msgf("cannot cast APPLICATION_PORT env to integer")
	}

	log.Info().Msgf("starting the server on port :%s", port)

	//http.Server instance
	s := &http.Server{
		Addr:         fmt.Sprintf(":%d", srvPort),
		Handler:      router,
		TLSConfig:    nil,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Info().Msgf("Starting server on port %d", srvPort)

		err := s.ListenAndServe()
		if err != nil {
			log.Fatal().Msgf(err.Error())
		}
	}()

	//trap os.Signal and gracefully shutdown the server
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	signal.Notify(sigCh, os.Kill)

	sig := <-sigCh

	log.Info().Msgf("Graceful shutdown with signal %s \n", sig)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.Shutdown(ctx)
}
