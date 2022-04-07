package sql

import (
	"context"
	"database/sql"
	"regexp"
	"time"

	"agola.io/agola/internal/errors"

	"github.com/lib/pq"
	"github.com/mattn/go-sqlite3"
)

type Type string

const (
	Sqlite3  Type = "sqlite3"
	Postgres Type = "postgres"

	maxTxRetries = 20
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
			{matchLiteral("timestampt"), "datetime"},
			{matchLiteral("timestamptz"), "datetime"},
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
		return nil, errors.Wrap(err, "sql open err")
	}

	db := &DB{
		db:   sqldb,
		data: data,
	}

	return db, nil
}

func (db *DB) Type() Type {
	return db.data.t
}

// Tx wraps a sql.Tx to:
// * Setup the transaction (set isolation levels etc...)
// * Apply some statement mutations before executing it
type Tx struct {
	db  *DB
	tx  *sql.Tx
	ctx context.Context
}

func (db *DB) Close() error {
	return errors.WithStack(db.db.Close())
}

func (db *DB) Conn(ctx context.Context) (*sql.Conn, error) {
	c, err := db.db.Conn(ctx)
	return c, errors.WithStack(err)
}

func (db *DB) NewUnstartedTx() *Tx {
	return &Tx{
		db: db,
	}
}

func (db *DB) NewTx(ctx context.Context) (*Tx, error) {
	tx := db.NewUnstartedTx()
	if err := tx.Start(ctx); err != nil {
		return nil, errors.WithStack(err)
	}

	return tx, nil
}

func (db *DB) Do(ctx context.Context, f func(tx *Tx) error) error {
	retries := 0
	for {
		err := db.do(ctx, f)
		if err != nil {
			switch db.data.t {
			case Sqlite3:
				var sqerr sqlite3.Error
				if errors.As(err, &sqerr) {
					if sqerr.Code == sqlite3.ErrLocked {
						retries++
						if retries <= maxTxRetries {
							continue
						}
					}
				}

			case Postgres:
				var pqerr *pq.Error
				if errors.As(err, &pqerr) {
					// retry on postgres serialization error
					if pqerr.Code == "40001" {
						retries++
						if retries <= maxTxRetries {
							continue
						}
					}
				}
			}
		}
		return errors.WithStack(err)
	}
}

func (db *DB) do(ctx context.Context, f func(tx *Tx) error) error {
	tx, err := db.NewTx(ctx)
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if err = f(tx); err != nil {
		_ = tx.Rollback()
		return errors.WithStack(err)
	}
	return tx.Commit()
}

func (tx *Tx) DBType() Type {
	return tx.db.data.t
}

func (tx *Tx) Start(ctx context.Context) error {
	wtx, err := tx.db.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.WithStack(err)
	}

	tx.tx = wtx
	tx.ctx = ctx

	if err := tx.setup(); err != nil {
		_ = tx.Rollback()
		return errors.WithStack(err)
	}

	return nil
}

func (tx *Tx) setup() error {
	// We MUST use serializable isolation levels in every db since it's the
	// best way to avoid concurrency issues. Sqlite is serializable by default
	// since only a single write transaction can be executed at a time
	switch tx.db.data.t {
	case Postgres:
		if _, err := tx.tx.ExecContext(tx.ctx, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"); err != nil {
			return errors.WithStack(err)
		}
	case Sqlite3:
		// Avoid sqlite deadlocks error when more than one tx started as
		// readonly tries to become readwrite by immediately starting a read
		// write transaction
		// TODO(sgotti) in future add a way to specify if the tx will be readonly or readwrite
		if _, err := tx.tx.ExecContext(tx.ctx, "ROLLBACK; BEGIN IMMEDIATE"); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func (tx *Tx) Commit() error {
	if tx.tx == nil {
		return nil
	}
	return errors.WithStack(tx.tx.Commit())
}

func (tx *Tx) Rollback() error {
	if tx.tx == nil {
		return nil
	}
	return errors.WithStack(tx.tx.Rollback())
}

func (tx *Tx) Exec(query string, args ...interface{}) (sql.Result, error) {
	query = tx.db.data.translate(query)
	r, err := tx.tx.ExecContext(tx.ctx, query, tx.db.data.translateArgs(args)...)
	return r, errors.WithStack(err)
}

func (tx *Tx) Query(query string, args ...interface{}) (*sql.Rows, error) {
	query = tx.db.data.translate(query)
	r, err := tx.tx.QueryContext(tx.ctx, query, tx.db.data.translateArgs(args)...)
	return r, errors.WithStack(err)
}

func (tx *Tx) QueryRow(query string, args ...interface{}) *sql.Row {
	query = tx.db.data.translate(query)
	return tx.tx.QueryRowContext(tx.ctx, query, tx.db.data.translateArgs(args)...)
}

func (tx *Tx) CurTime() (time.Time, error) {
	switch tx.db.data.t {
	case Sqlite3:
		var timestring string
		if err := tx.QueryRow("select now()").Scan(&timestring); err != nil {
			return time.Time{}, errors.WithStack(err)
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05.999999999", timestring, time.UTC)
		return t, errors.WithStack(err)
	case Postgres:
		var now time.Time
		if err := tx.QueryRow("select now()").Scan(&now); err != nil {
			return time.Time{}, errors.WithStack(err)
		}
		return now, nil
	}
	return time.Time{}, errors.New("unknown db type")
}
