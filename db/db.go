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
		_, err = dbm.db.Exec("DROP TABLE IF EXISTS users")
		if err != nil {
			return err
		}
	}
	_, err = dbm.db.Exec(`
		CREATE TABLE IF NOT EXISTS 
		users (
			id      INT PRIMARY KEY AUTO_INCREMENT,
			email   TEXT NOT NULL,
			passwd  TEXT NOT NULL
		)
	`)
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

	resut, err := tx.Exec("INSERT INTO users (email, passwd) VALUES (?, ?)", user.Email, user.Passwd)
	if err != nil {
		return -1, err
	}
	id, err = resut.LastInsertId()
	if err != nil {
		return -1, err
	}

	if err = tx.Commit(); err != nil {
		return -1, err
	}
	return id, nil
}
