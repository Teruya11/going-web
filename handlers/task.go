package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"going-web/db"
)

/*
	id      INT PRIMARY KEY AUTO_INCREMENT,
	done    BOOL NOT NULL,
	title   TEXT NOT NULL,
	user_id INT NOT NULL,
	FOREIGN KEY (user_id) REFERENCES users(id)

*/

type NewTaskRequest struct {
	Title  string `json:"title"`
	UserID int64  `json:"user_id"`
	Done   bool   `json:"done"`
}

type Task struct {
	Title  string
	ID     int64
	UserID int64
	Done   bool
}

type TaskDB interface {
	SaveTask(task *db.NewTaskRequest) (id int64, err error)
}

func NewTask(dbm TaskDB) http.HandlerFunc {
	// Receive request and save user locally
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		if r.Method != http.MethodPost {
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return
		}

		var task db.NewTaskRequest
		err = json.NewDecoder(r.Body).Decode(&task)
		if err != nil {
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return
		}

		_, err = dbm.SaveTask(&task)
		if err != nil {
			log.Fatal(err)
			return
		}
		w.Write([]byte("Task saved successfully"))
	}
}
