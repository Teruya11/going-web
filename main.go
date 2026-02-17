package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"going-web/db"
	"going-web/jwt"
)

func main() {
	var err error

	var dbm db.DBManager
	err = dbm.Connect("authie", "authie", "authie")
	if err != nil {
		log.Fatal(err)
	}
	err = dbm.CreateTables(true)
	if err != nil {
		log.Fatal(err)
	}
	id, err := dbm.SaveUser(&db.UserRequest{Email: "foo@bar.com", Passwd: "foo"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(id, err)

	usr, err := dbm.GetUserFromEmail("foo@bar.com")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", usr)

	secret := []byte("secret")
	tkn, err := jwt.New(1, secret)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(tkn)
	p, err := jwt.Decode(tkn, secret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%v\n", p)
	fmt.Printf("%v\n", jwt.Verify(tkn, secret))

	mux := http.NewServeMux()
	mux.HandleFunc("/register", registerHandler(&dbm, secret))
	mux.HandleFunc("/time", middleware(secret, timeHandler(time.RFC1123)))

	const port = 3000
	log.Printf("Listening on %d\n", port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", port), mux)
	log.Fatal(err)
}

func registerHandler(dbm *db.DBManager, secret []byte) http.HandlerFunc {
	// Receive request and save user locally
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return
		}
		var user db.UserRequest
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return
		}

		found, _ := dbm.GetUserFromEmail(user.Email)
		if found != nil {
			http.Error(w, "409 User Already Exists", http.StatusConflict)
			return
		}

		id, err := dbm.SaveUser(&user)
		if err != nil {
			log.Fatal(err)
			return
		}
		// Give Jwt token
		tkn, err := jwt.New(id, secret)
		if err != nil {
			log.Fatal(err)
			return
		}
		_, err = w.Write([]byte(tkn))
		if err != nil {
			log.Fatal(err)
			return
		}
	}
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

// Accept interfaces, return types
func timeHandler(format string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tm := time.Now().Format(format)
		_, err := w.Write([]byte("The time is " + tm))
		if err != nil {
			log.Fatal(err)
		}
	}
}
