package manager

import (
	"context"
	stdsql "database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	sq "github.com/huandu/go-sqlbuilder"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/lock"
	"agola.io/agola/internal/sqlg/sql"
)

const (
	MaxQueryLimit = 100

	DBLockName = "dbupdate"
)

const (
	dbVersionTableName = "dbversion"
	sequenceTableName  = "sequence_t"
)

var (
	dbVersionTableDDLPostgres = fmt.Sprintf("create table if not exists %s (version int not null, time timestamptz not null)", dbVersionTableName)
	dbVersionTableDDLSqlite   = fmt.Sprintf("create table if not exists %s (version int not null, time text not null)", dbVersionTableName)

	sequenceTableDDLSqlite = fmt.Sprintf("create table if not exists %s (name varchar UNIQUE NOT NULL, value bigint NOT NULL, PRIMARY KEY (name))", sequenceTableName)
)

type DB interface {
	DBType() sql.Type
	Version() uint

	Do(ctx context.Context, f func(tx *sql.Tx) error) error

	MigrateFuncs() map[uint]sqlg.MigrateFunc

	DDL() []string
	ObjectsInfo() []sqlg.ObjectInfo

	UnmarshalExportObject(data []byte) (sqlg.Object, error)
	InsertRawObject(tx *sql.Tx, obj sqlg.Object) error
	SelectObject(kind string) *sq.SelectBuilder
	FetchObjects(tx *sql.Tx, kind string, q sq.Builder) ([]sqlg.Object, error)
	ObjectToExportJSON(obj sqlg.Object, e *json.Encoder) error

	Sequences() []sqlg.Sequence
	GetSequence(tx *sql.Tx, sequenceName string) (uint64, error)
	PopulateSequences(tx *sql.Tx) error
}

type DBManager struct {
	log zerolog.Logger
	d   DB
	lf  lock.LockFactory

	lock lock.Lock
	mu   sync.Mutex
}

func NewDBManager(log zerolog.Logger, d DB, lf lock.LockFactory) *DBManager {
	return &DBManager{log: log, d: d, lf: lf}
}

func (m *DBManager) sqFlavor() sq.Flavor {
	switch m.d.DBType() {
	case sql.Postgres:
		return sq.PostgreSQL
	case sql.Sqlite3:
		return sq.SQLite
	}

	return sq.PostgreSQL
}

func (m *DBManager) exec(tx *sql.Tx, rq sq.Builder) (stdsql.Result, error) {
	q, args := rq.BuildWithFlavor(m.sqFlavor())
	// d.log.Debug().Msgf("q: %s, args: %s", q, util.Dump(args))

	r, err := tx.Exec(q, args...)
	return r, errors.WithStack(err)
}

func (m *DBManager) Lock(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lock != nil {
		return errors.Errorf("lock already held")
	}

	// TODO(sgotti) this lock is optimistic and doesn't ensure real exclusive operations on the database
	l := m.lf.NewLock(DBLockName)
	if err := l.Lock(ctx); err != nil {
		return errors.Wrap(err, "failed to acquire database lock")
	}

	m.lock = l

	return nil
}

func (m *DBManager) Unlock() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lock == nil {
		return errors.Errorf("no lock")
	}

	return errors.WithStack(m.lock.Unlock())
}

func (m *DBManager) WantedVersion() uint {
	return m.d.Version()
}

func (m *DBManager) DDL() []string {
	return m.d.DDL()
}

func (m *DBManager) GetVersion(ctx context.Context) (uint, error) {
	var curVersion uint
	err := m.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		curVersion, err = m.getVersion(tx)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return 0, errors.WithStack(err)
	}

	return curVersion, nil
}

func (m *DBManager) getVersion(tx *sql.Tx) (uint, error) {
	var curVersion *uint
	s := sq.NewSelectBuilder()
	q, args := s.Select("max(version)").From(dbVersionTableName).Build()
	if err := tx.QueryRow(q, args...).Scan(&curVersion); err != nil {
		return 0, errors.Wrapf(err, "cannot get current %s version", dbVersionTableName)
	}

	if curVersion == nil {
		return 0, nil
	}

	return *curVersion, nil
}

func (m *DBManager) CheckVersion(curVersion, wantedVersion uint) error {
	if curVersion > wantedVersion {
		return errors.Errorf("current db schema version %d is greater than the supported db schema version %d", curVersion, wantedVersion)
	}

	return nil
}

func (m *DBManager) CheckMigrationRequired(curVersion, wantedVersion uint) (bool, error) {
	if err := m.CheckVersion(curVersion, wantedVersion); err != nil {
		return false, errors.WithStack(err)
	}

	if curVersion < wantedVersion {
		return true, nil
	}

	return false, nil
}

func (m *DBManager) setVersion(tx *sql.Tx, version uint) error {
	q := sq.NewInsertBuilder()
	q.InsertInto(dbVersionTableName).Cols("version", "time").Values(version, time.Now())
	if _, err := m.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to update %s table", dbVersionTableName)
	}

	return nil
}

func (m *DBManager) Drop(ctx context.Context) error {
	err := m.d.Do(ctx, func(tx *sql.Tx) error {
		switch m.d.DBType() {
		case sql.Postgres:
			if _, err := tx.Exec("SET CONSTRAINTS ALL DEFERRED"); err != nil {
				return errors.WithStack(err)
			}
		case sql.Sqlite3:
			if _, err := tx.Exec("PRAGMA defer_foreign_keys = ON"); err != nil {
				return errors.WithStack(err)
			}
		}

		for _, oi := range m.d.ObjectsInfo() {
			switch m.d.DBType() {
			case sql.Postgres:
				if _, err := tx.Exec(fmt.Sprintf("drop table if exists %s cascade", oi.Table)); err != nil {
					return errors.Wrapf(err, "failed to drop table %s", oi.Table)
				}
			case sql.Sqlite3:
				if _, err := tx.Exec(fmt.Sprintf("drop table if exists %s", oi.Table)); err != nil {
					return errors.Wrapf(err, "failed to drop table %s", oi.Table)
				}
			}
		}

		for _, tableName := range []string{dbVersionTableName, sequenceTableName} {
			switch m.d.DBType() {
			case sql.Postgres:
				if _, err := tx.Exec(fmt.Sprintf("drop table if exists %s cascade", tableName)); err != nil {
					return errors.Wrapf(err, "failed to drop table %s", tableName)
				}
			case sql.Sqlite3:
				if _, err := tx.Exec(fmt.Sprintf("drop table if exists %s", tableName)); err != nil {
					return errors.Wrapf(err, "failed to drop table %s", tableName)
				}
			}
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (m *DBManager) Setup(ctx context.Context) error {
	var dbVersionTableDDL string
	switch m.d.DBType() {
	case sql.Postgres:
		dbVersionTableDDL = dbVersionTableDDLPostgres
	case sql.Sqlite3:
		dbVersionTableDDL = dbVersionTableDDLSqlite
	}

	err := m.d.Do(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(dbVersionTableDDL); err != nil {
			return errors.Wrapf(err, "failed to create %s table", dbVersionTableName)
		}

		if m.d.DBType() == sql.Sqlite3 {
			if _, err := tx.Exec(sequenceTableDDLSqlite); err != nil {
				return errors.Wrapf(err, "failed to create %s table", sequenceTableDDLSqlite)
			}
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
