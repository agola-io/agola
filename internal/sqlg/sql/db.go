package sql

import (
	"context"
	"database/sql"
	"math/rand"
	"time"

	"github.com/gofrs/uuid"
	"github.com/lib/pq"
	"github.com/sorintlab/errors"
)

type Type string

const (
	Sqlite3  Type = "sqlite3"
	Postgres Type = "postgres"

	maxTxRetries = 20
)

type dbData struct {
	t                 Type
	supportsTimezones bool
}

var (
	dbDataPostgres = dbData{
		t:                 Postgres,
		supportsTimezones: true,
	}

	dbDataSQLite3 = dbData{
		t:                 Sqlite3,
		supportsTimezones: false,
	}
)

// translateArgs translates query parameters that may be unique to
// a specific SQL flavor. For example, standardizing "time.Time"
// types to UTC for clients that don't provide timezone support.
func (t dbData) translateArgs(args []any) []any {
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
	id  string
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
		id: uuid.Must(uuid.NewV4()).String(),
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
				if checkSqlite3RetryError(err) {
					retries++
					if retries <= maxTxRetries {
						time.Sleep(time.Duration(int64(rand.Intn(20))) * time.Millisecond)
						continue
					}
				}

			case Postgres:
				var pqerr *pq.Error
				if errors.As(err, &pqerr) {
					// retry on postgres serialization error
					if pqerr.Code == "40001" {
						retries++
						if retries <= maxTxRetries {
							time.Sleep(time.Duration(int64(rand.Intn(20))) * time.Millisecond)
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

func (tx *Tx) ID() string {
	if tx == nil {
		return ""
	}

	return tx.id
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
		// Always set timezone for retrieving times to UTC. This avoid some
		// issues in lib pq handling timezones reported by postgres with also
		// seconds. This happens for example when writing a golang "zero" time
		// (time.Time{}) since it's reported by postgres as something like '0001-01-01 00:49:56+00:49:56'
		if _, err := tx.tx.ExecContext(tx.ctx, "SET TIME ZONE UTC"); err != nil {
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

func (tx *Tx) Exec(query string, args ...any) (sql.Result, error) {
	r, err := tx.tx.ExecContext(tx.ctx, query, tx.db.data.translateArgs(args)...)
	return r, errors.WithStack(err)
}

func (tx *Tx) Query(query string, args ...any) (*sql.Rows, error) {
	r, err := tx.tx.QueryContext(tx.ctx, query, tx.db.data.translateArgs(args)...)
	return r, errors.WithStack(err)
}

func (tx *Tx) QueryRow(query string, args ...any) *sql.Row {
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
