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

type Task struct {
	Title  string
	ID     int64
	UserID int64
	Done   bool
}

type TaskDB interface {
	SaveTask(task *db.NewTaskRequest) (id int64, err error)
	GetTasksFromUser(userID int64) (tasks []db.Task, err error)
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

func GetTasks(dbm TaskDB) http.HandlerFunc {
	// Receive request and save user locally
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		if r.Method != http.MethodPost {
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return
		}

		var task db.GetTasksRequest
		err = json.NewDecoder(r.Body).Decode(&task)
		if err != nil {
			http.Error(w, "400 Bad Request", http.StatusBadRequest)
			return
		}

		var tasks []db.Task
		tasks, err = dbm.GetTasksFromUser(task.UserID)
		if err != nil {
			log.Fatal(err)
			return
		}

		var response []byte
		response, err = json.Marshal(tasks)
		if err != nil {
			log.Fatal(err)
			return
		}
		w.Write(response)
	}
}
