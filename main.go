package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type UserRequest struct {
	User   string `json:"user"`
	Passwd string `json:"passwd"`
}

func main() {
	db := make(map[string]string)
	var err error

	var dbm DBManager
	err = dbm.Connect("authie", "authie", "authie")
	if err != nil {
		log.Fatal(err)
	}
	err = dbm.CreateTables(true)
	if err != nil {
		log.Fatal(err)
	}

	secret := []byte("secret")
	tkn, err := generateJwt("admin", secret)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(tkn)
	h, p, err := decodeJwt(tkn, secret)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v %v\n", h, p)
	fmt.Printf("%v\n", isTokenValid(tkn, secret))

	mux := http.NewServeMux()
	mux.HandleFunc("/user", userHandler(&db, secret))
	mux.HandleFunc("/time", middleware(timeHandler(time.RFC1123), &db))

	const port = 3000
	log.Printf("Listening on %d\n", port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", port), mux)
	log.Fatal(err)
}

func userHandler(db *map[string]string, secret []byte) http.HandlerFunc {
	// Receive request and save user locally
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return
		}
		var user UserRequest
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return
		}
		if _, exists := (*db)[user.User]; exists {
			http.Error(w, "409 User Already Exists", http.StatusConflict)
			return
		}
		(*db)[user.User] = user.Passwd
		// Give Jwt token
		tkn, err := generateJwt(user.User, secret)
		if err != nil {
			log.Fatal(err)
			return
		}
		w.Write([]byte(tkn))
	}
}

func middleware(handler http.Handler, db *map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		_, tkn, ok := strings.Cut(auth, "Bearer ")
		if !ok {
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return
		}
		log.Println(tkn)
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
