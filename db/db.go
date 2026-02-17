package db

import (
	"database/sql"

	"github.com/go-sql-driver/mysql"
)

type DBManager struct {
	db *sql.DB
}

type User struct {
	ID     int32
	Name   string
	Passwd string
}

func (dbm *DBManager) Connect(user string, passwd string, dbname string) error {
	cfg := mysql.NewConfig()
	cfg.User = user
	cfg.Passwd = passwd
	cfg.DBName = dbname

	var err error
	dbm.db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return err
	}

	return nil
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
			id 			INT PRIMARY KEY,
			name 		VARCHAR(256) NOT NULL,
			passwd_hash VARCHAR(512) NOT NULL
		)
	`)
	return err
}

func (dbm *DBManager) GetUserFromID(id int32) (*User, error) {
	var err error
	q, err := dbm.db.Query("SELECT * FROM users WHERE id = ?", id)
	if err != nil {
		return nil, err
	}
	defer q.Close()

	if !q.Next() {
		return nil, q.Err()
	}
	var user User
	err = q.Scan(&user.ID, &user.Name, &user.Passwd)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
