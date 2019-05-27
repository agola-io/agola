// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package db

import (
	"context"
	"database/sql"
	"regexp"
	"time"

	_ "github.com/mattn/go-sqlite3"
	errors "golang.org/x/xerrors"
)

type Type string

const (
	Sqlite3  Type = "sqlite3"
	Postgres Type = "postgres"
)

type dbData struct {
	t                 Type
	queryReplacers    []replacer
	supportsTimezones bool
}

type replacer struct {
	re   *regexp.Regexp
	with string
}

// match a postgres query bind variable. E.g. "$1", "$12", etc.
var bindRegexp = regexp.MustCompile(`\$\d+`)

func matchLiteral(s string) *regexp.Regexp {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(s) + `\b`)
}

var (
	dbDataPostgres = dbData{
		t:                 Postgres,
		supportsTimezones: true,
		queryReplacers: []replacer{
			// Remove sqlite3 only statements
			{regexp.MustCompile(`--SQLITE3\n.*`), ""},
		},
	}

	dbDataSQLite3 = dbData{
		t:                 Sqlite3,
		supportsTimezones: false,
		queryReplacers: []replacer{
			{bindRegexp, "?"},
			{matchLiteral("true"), "1"},
			{matchLiteral("false"), "0"},
			{matchLiteral("boolean"), "integer"},
			{matchLiteral("bytea"), "blob"},
			// timestamp is a declared type suported by the go-sqlite3 driver
			{matchLiteral("timestamptz"), "timestamp"},
			// convert now to the max precision time available with sqlite3
			{regexp.MustCompile(`\bnow\(\)`), "strftime('%Y-%m-%d %H:%M:%f', 'now')"},
			{regexp.MustCompile(`select pg_advisory_xact_lock\(.*`), "select 1"},
			{regexp.MustCompile(`notify\s+.*`), "select 1"},
			// Remove postgres only statements
			{regexp.MustCompile(`--POSTGRES\n.*`), ""},
		},
	}
)

func (t dbData) translate(query string) string {
	for _, r := range t.queryReplacers {
		query = r.re.ReplaceAllString(query, r.with)
	}
	return query
}

// translateArgs translates query parameters that may be unique to
// a specific SQL flavor. For example, standardizing "time.Time"
// types to UTC for clients that don't provide timezone support.
func (t dbData) translateArgs(args []interface{}) []interface{} {
	if t.supportsTimezones {
		return args
	}

	for i, arg := range args {
		if t, ok := arg.(time.Time); ok {
			args[i] = t.UTC()
		}
	}
	return args
}

// DB wraps a sql.DB to add special behaviors based on the db type
type DB struct {
	db   *sql.DB
	data dbData
}

func NewDB(dbType Type, dbConnString string) (*DB, error) {
	var data dbData
	var driverName string
	switch dbType {
	case Postgres:
		data = dbDataPostgres
		driverName = "postgres"
	case Sqlite3:
		data = dbDataSQLite3
		driverName = "sqlite3"
		dbConnString = "file:" + dbConnString + "?cache=shared&_journal=wal&_foreign_keys=true&_case_sensitive_like=false"
	default:
		return nil, errors.New("unknown db type")
	}

	sqldb, err := sql.Open(driverName, dbConnString)
	if err != nil {
		return nil, err
	}

	db := &DB{
		db:   sqldb,
		data: data,
	}

	return db, nil
}

// Tx wraps a sql.Tx to offer:
// * apply some statement mutations before executing it
// * locking around concurrent executions of statements (since the underlying
// sql driver doesn't support concurrent statements on the same
// connection/transaction)
type Tx struct {
	db *DB
	tx *sql.Tx
}

func (db *DB) Close() error {
	return db.db.Close()
}

func (db *DB) Conn() (*sql.Conn, error) {
	return db.db.Conn(context.TODO())
}

func (db *DB) NewUnstartedTx() *Tx {
	return &Tx{
		db: db,
	}
}

func (db *DB) NewTx() (*Tx, error) {
	tx := db.NewUnstartedTx()
	if err := tx.Start(); err != nil {
		return nil, err
	}

	return tx, nil
}

func (db *DB) Do(f func(tx *Tx) error) error {
	tx, err := db.NewTx()
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()
	if err = f(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (tx *Tx) Start() error {
	wtx, err := tx.db.db.Begin()
	if err != nil {
		return err
	}
	switch tx.db.data.t {
	case Postgres:
		if _, err := wtx.Exec("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"); err != nil {
			return err
		}
	}
	tx.tx = wtx
	return nil
}

func (tx *Tx) Commit() error {
	if tx.tx == nil {
		return nil
	}
	return tx.tx.Commit()
}

func (tx *Tx) Rollback() error {
	if tx.tx == nil {
		return nil
	}
	return tx.tx.Rollback()
}

func (tx *Tx) Exec(query string, args ...interface{}) (sql.Result, error) {
	query = tx.db.data.translate(query)
	r, err := tx.tx.Exec(query, tx.db.data.translateArgs(args)...)
	return r, err
}

func (tx *Tx) Query(query string, args ...interface{}) (*sql.Rows, error) {
	query = tx.db.data.translate(query)
	r, err := tx.tx.Query(query, tx.db.data.translateArgs(args)...)
	return r, err
}

func (tx *Tx) QueryRow(query string, args ...interface{}) *sql.Row {
	query = tx.db.data.translate(query)
	return tx.tx.QueryRow(query, tx.db.data.translateArgs(args)...)
}

func (tx *Tx) CurTime() (time.Time, error) {
	switch tx.db.data.t {
	case Sqlite3:
		var timestring string
		if err := tx.QueryRow("select now()").Scan(&timestring); err != nil {
			return time.Time{}, err
		}
		return time.ParseInLocation("2006-01-02 15:04:05.999999999", timestring, time.UTC)
	case Postgres:
		var now time.Time
		if err := tx.QueryRow("select now()").Scan(&now); err != nil {
			return time.Time{}, err
		}
		return now, nil
	}
	return time.Time{}, errors.New("unknown db type")
}
