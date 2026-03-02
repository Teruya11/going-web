package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"going-web/db"
	"going-web/handlers"
	"going-web/jwt"
)

func main() {
	var err error

	var dbm *db.DBManager = new(db.DBManager)
	err = dbm.Connect("authie", "authie", "authie")
	if err != nil {
		log.Fatal(err)
	}
	err = dbm.CreateTables(true)
	if err != nil {
		log.Fatal(err)
	}

	var secret []byte = []byte("secret")
	var mux *http.ServeMux = http.NewServeMux()
	mux.HandleFunc("/register", handlers.RegisterHandler(dbm, secret))
	mux.HandleFunc("/login", handlers.LoginHandler(dbm, secret))
	mux.HandleFunc("/time", middleware(secret, timeHandler(time.RFC1123)))

	const port int = 3000
	log.Printf("Listening on %d\n", port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", port), mux)
	log.Fatal(err)
}

func middleware(secret []byte, handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var authHeader string
		var ok bool
		var tkn string
		var p *jwt.Payload
		var err error

		authHeader = r.Header.Get("Authorization")
		tkn, ok = strings.CutPrefix(authHeader, "Bearer ")
		if !ok {
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return
		}

		if ok = jwt.Verify(tkn, secret); !ok {
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}

		p, err = jwt.Decode(tkn, secret)
		if err != nil {
			log.Fatal(err)
			return
		}
		then, err := time.Parse(time.RFC1123, p.Time)
		if err != nil {
			log.Fatal(err)
			return
		}
		elapsed := time.Since(then).Hours()
		if elapsed > p.Dur {
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}

		handler.ServeHTTP(w, r)
	}
}

func timeHandler(format string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		tm := time.Now().Format(format)
		_, err = w.Write([]byte("The time is " + tm))
		if err != nil {
			log.Fatal(err)
		}
	}
}
