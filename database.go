package main

import (
	"database/sql"

	"github.com/go-sql-driver/mysql"
)

type DBManager struct {
	db *sql.DB
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
