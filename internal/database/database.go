package database

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

// InitDB initializes the database and creates necessary tables.
// dsn is the SQLite data source name supplied via the DATABASE_DSN
// environment variable (loaded through config.Config.DatabaseDSN).
// This avoids hardcoding connection details in source code (CWE-547).
func InitDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	// Create table
	_, err = db.Exec(`
		CREATE TABLE repos (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			git_url TEXT NOT NULL,
			repo_type TEXT NOT NULL,
			created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return nil, err
	}

	log.Println("Initialized SQL database (SQLite in-memory)")
	return db, nil
}
