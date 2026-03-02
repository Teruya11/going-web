package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"going-web/db"
	"going-web/jwt"
)

type UserDB interface {
	GetUserFromEmail(email string) (user *db.User, err error)
	SaveUser(user *db.UserRequest) (id int64, err error)
}

func Register(dbm UserDB, secret []byte) http.HandlerFunc {
	// Receive request and save user locally
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		if r.Method != http.MethodPost {
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return
		}

		var user db.UserRequest
		err = json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return
		}

		var found *db.User
		found, _ = dbm.GetUserFromEmail(user.Email)
		if found != nil {
			http.Error(w, "409 User Already Exists", http.StatusConflict)
			return
		}

		var id int64
		id, err = dbm.SaveUser(&user)
		if err != nil {
			log.Fatal(err)
			return
		}
		// Give Jwt token
		var tkn string
		tkn, err = jwt.New(id, secret)
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

func Login(dbm UserDB, secret []byte) http.HandlerFunc {
	// Receive request and save user locally
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		if r.Method != http.MethodPost {
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return
		}

		var user db.UserRequest
		err = json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return
		}

		var found *db.User
		found, _ = dbm.GetUserFromEmail(user.Email)
		if found == nil || found.Passwd != user.Passwd {
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}

		// Give Jwt token
		var tkn string
		tkn, err = jwt.New(found.ID, secret)
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
