// Package db contains database code
package db

import (
	"database/sql"

	"github.com/go-sql-driver/mysql"
)

type UserRequest struct {
	Email  string `json:"email"`
	Passwd string `json:"passwd"`
}

type User struct {
	ID     int64
	Email  string
	Passwd string
}

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

type DBManager struct {
	db *sql.DB
}

func (dbm *DBManager) Connect(user string, passwd string, dbname string) error {
	var err error

	cfg := mysql.NewConfig()
	cfg.User = user
	cfg.Passwd = passwd
	cfg.DBName = dbname

	dbm.db, err = sql.Open("mysql", cfg.FormatDSN())
	return err
}

func (dbm *DBManager) CreateTables(drop bool) error {
	var err error

	if drop {
		_, err = dbm.db.Exec("DROP TABLE IF EXISTS tasks, users")
		if err != nil {
			return err
		}
	}
	const createUsersTable = `
		CREATE TABLE IF NOT EXISTS 
		users (
			id      INT PRIMARY KEY AUTO_INCREMENT,
			email   TEXT NOT NULL,
			passwd  TEXT NOT NULL
		)
	`
	_, err = dbm.db.Exec(createUsersTable)
	if err != nil {
		return err
	}

	const createTasksTable = `
		CREATE TABLE IF NOT EXISTS 
		tasks (
			id      INT PRIMARY KEY AUTO_INCREMENT,
			done    BOOL NOT NULL,
			title   TEXT NOT NULL,
			user_id INT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)
	`
	_, err = dbm.db.Exec(createTasksTable)
	return err
}

func (dbm *DBManager) GetUserFromEmail(email string) (user *User, err error) {
	q, err := dbm.db.Query("SELECT * FROM users WHERE email = ?", email)
	if err != nil {
		return nil, err
	}
	defer q.Close()

	if !q.Next() {
		return nil, q.Err()
	}
	user = new(User)
	err = q.Scan(&user.ID, &user.Email, &user.Passwd)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (dbm *DBManager) SaveUser(user *UserRequest) (id int64, err error) {
	tx, err := dbm.db.Begin()
	if err != nil {
		return -1, err
	}
	defer tx.Rollback()

	result, err := tx.Exec("INSERT INTO users (email, passwd) VALUES (?, ?)", user.Email, user.Passwd)
	if err != nil {
		return -1, err
	}
	id, err = result.LastInsertId()
	if err != nil {
		return -1, err
	}

	if err = tx.Commit(); err != nil {
		return -1, err
	}
	return id, nil
}

func (dbm *DBManager) SaveTask(task *NewTaskRequest) (id int64, err error) {
	var tx *sql.Tx
	tx, err = dbm.db.Begin()
	if err != nil {
		return -1, err
	}
	defer tx.Rollback()

	var result sql.Result
	result, err = tx.Exec("INSERT INTO tasks (title, done, user_id) VALUES (?, ?, ?)", task.Title, task.Done, task.UserID)
	if err != nil {
		return -1, err
	}
	id, err = result.LastInsertId()
	if err != nil {
		return -1, err
	}

	if err = tx.Commit(); err != nil {
		return -1, err
	}
	return id, nil
}
