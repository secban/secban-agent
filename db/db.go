package db

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type LogEntry struct {
	IP     string
	Ban    time.Time
	Events string
}

const (
	dbOptions       = "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&synchronous(normal)&optimize"
	maxOpenConns    = 1
	maxIdleConns    = 1
	connMaxLifetime = 0
	dirMode         = 0o770
	dbFileMode      = 0o660
)

var database *sql.DB //nolint:gochecknoglobals

func Init(ctx context.Context, dbPath string) error {
	if database != nil {
		return nil
	}

	var err error

	database, err = New(ctx, dbPath)
	if err != nil {
		return err
	}

	return CreateSchema(ctx, database)
}

func New(_ context.Context, dbPath string) (*sql.DB, error) {
	if dbPath != ":memory:" {
		createErr := createDB(dbPath)
		if createErr != nil {
			return nil, createErr
		}
	}

	db, openErr := sql.Open(
		"sqlite",
		"file:"+dbPath+dbOptions,
	)
	if openErr != nil {
		return nil, openErr
	}

	db.SetMaxOpenConns(maxOpenConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetMaxIdleConns(maxIdleConns)

	return db, nil
}

func createDB(dbPath string) error {
	dirPath := filepath.Dir(dbPath)

	createDirErr := os.MkdirAll(dirPath, os.FileMode(dirMode))
	if createDirErr != nil {
		return createDirErr
	}

	file, createFileErr := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, os.FileMode(dbFileMode))
	if createFileErr != nil {
		return createFileErr
	}
	defer file.Close()

	chmodErr := os.Chmod(dbPath, os.FileMode(dbFileMode))
	if chmodErr != nil {
		return chmodErr
	}

	return nil
}

func DB(ctx context.Context) (*sql.DB, error) {
	if database == nil {
		return nil, errors.New("database is not initialized; call db.Init() first")
	}

	return database, nil
}

func Close() error {
	if database == nil {
		return nil
	}

	err := CloseDB(database)
	database = nil

	return err
}

func CloseDB(db *sql.DB) error {
	return db.Close()
}

func CreateSchema(ctx context.Context, db *sql.DB) error {
	var err error
	for attempt := range 3 {
		_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS bans (
			ip TEXT,
			ban TIMESTAMP NOT NULL,
			rule TEXT NOT NULL,
			events BLOB,
			PRIMARY KEY(ip, ban)
		);`,
		)
		if err == nil || !strings.Contains(err.Error(), "database is locked") {
			return err
		}

		time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}

	return err
}
