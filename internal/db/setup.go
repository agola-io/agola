package db

import (
	"context"
	stdsql "database/sql"
	"fmt"
	"time"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/lock"
	"agola.io/agola/internal/sql"
	stypes "agola.io/agola/services/types"

	sq "github.com/Masterminds/squirrel"
	"github.com/rs/zerolog"
)

const (
	MaxQueryLimit = 100

	DBLockName = "dbupdate"
)

type ObjectData struct {
	id       string
	revision uint64
	data     []byte
}

var ErrConcurrent = errors.New("concurrent update")

const (
	dataTablesVersionTableName  = "datatablesversion"
	queryTablesVersionTableName = "querytablesversion"
)

var (
	dataTablesVersionTableDDL  = fmt.Sprintf("create table if not exists %s (version int not null, time timestamptz not null)", dataTablesVersionTableName)
	queryTablesVersionTableDDL = fmt.Sprintf("create table if not exists %s (version int not null, time timestamptz not null)", queryTablesVersionTableName)
)

var sb = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

type ObjectInfo struct {
	Name  string
	Table string
}

type DB interface {
	Do(ctx context.Context, f func(tx *sql.Tx) error) error
	Exec(tx *sql.Tx, rq sq.Sqlizer) (stdsql.Result, error)
	Query(tx *sql.Tx, rq sq.Sqlizer) (*stdsql.Rows, error)

	DataTablesVersion() uint
	QueryTablesVersion() uint

	DTablesStatements() []string
	QTablesStatements() []string
	ObjectsInfo() []ObjectInfo

	UnmarshalObject(data []byte) (stypes.Object, error)
	InsertRawObject(tx *sql.Tx, obj stypes.Object) ([]byte, error)
	InsertObjectQ(tx *sql.Tx, obj stypes.Object, data []byte) error
}

func checkVersion(tx *sql.Tx, tableName string, version uint) (bool, error) {
	var curVersion *uint
	q, args, err := sb.Select("max(version)").From(tableName).ToSql()
	if err != nil {
		return false, errors.WithStack(err)
	}
	if err := tx.QueryRow(q, args...).Scan(&curVersion); err != nil {
		return false, errors.Wrapf(err, "cannot get current %s version", tableName)
	}

	if curVersion != nil && *curVersion == version {
		return true, nil
	}
	if curVersion != nil && *curVersion > version {
		return false, errors.Errorf("current db schema version %d is greater than the supported db schema version %d", *curVersion, version)
	}

	return false, nil
}

func setVersion(tx *sql.Tx, d DB, tableName string, version uint) error {
	q := sb.Insert(tableName).Columns("version", "time").Values(version, time.Now())
	if _, err := d.Exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to update %s table", tableName)
	}

	return nil
}

func Drop(ctx context.Context, log zerolog.Logger, d DB, lf lock.LockFactory) error {
	l := lf.NewLock(DBLockName)
	if err := l.Lock(ctx); err != nil {
		return errors.Wrap(err, "failed to acquire database lock")
	}
	defer func() { _ = l.Unlock() }()

	err := d.Do(ctx, func(tx *sql.Tx) error {
		for _, oi := range d.ObjectsInfo() {
			if _, err := tx.Exec(fmt.Sprintf("drop table if exists %s", oi.Table)); err != nil {
				return errors.Wrapf(err, "failed to drop table %s", oi.Table)
			}
		}

		for _, tableName := range []string{dataTablesVersionTableName, queryTablesVersionTableName} {
			if _, err := tx.Exec(fmt.Sprintf("drop table if exists %s", tableName)); err != nil {
				return errors.Wrapf(err, "failed to drop table %s", tableName)
			}
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func Setup(ctx context.Context, log zerolog.Logger, d DB, lf lock.LockFactory) error {
	err := d.Do(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(dataTablesVersionTableDDL); err != nil {
			return errors.Wrapf(err, "failed to create %s table", dataTablesVersionTableName)
		}

		if _, err := tx.Exec(queryTablesVersionTableDDL); err != nil {
			return errors.Wrapf(err, "failed to create %s table", queryTablesVersionTableName)
		}
		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	dataTablesNeedsMigrate := false
	queryTablesNeedsMigrate := false
	err = d.Do(ctx, func(tx *sql.Tx) error {
		ok, err := checkVersion(tx, dataTablesVersionTableName, d.DataTablesVersion())
		if err != nil {
			return errors.WithStack(err)
		}

		if !ok {
			dataTablesNeedsMigrate = true
		}

		ok, err = checkVersion(tx, queryTablesVersionTableName, d.QueryTablesVersion())
		if err != nil {
			return errors.WithStack(err)
		}

		if !ok {
			queryTablesNeedsMigrate = true
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	if !dataTablesNeedsMigrate && !queryTablesNeedsMigrate {
		return nil
	}

	// TODO(sgotti) this lock is optimistic and doesn't ensure real exclusive operations on the database
	// we must develop a better update path
	l := lf.NewLock(DBLockName)
	if err := l.Lock(ctx); err != nil {
		return errors.Wrap(err, "failed to acquire database lock")
	}
	defer func() { _ = l.Unlock() }()

	if dataTablesNeedsMigrate {
		log.Info().Msgf("migrating data tables")
		err = d.Do(ctx, func(tx *sql.Tx) error {
			for _, stmt := range d.DTablesStatements() {
				if _, err := tx.Exec(stmt); err != nil {
					return errors.Wrap(err, "creation failed")
				}
			}

			if err := setVersion(tx, d, dataTablesVersionTableName, d.DataTablesVersion()); err != nil {
				return errors.WithStack(err)
			}

			return nil
		})
		if err != nil {
			return errors.WithStack(err)
		}
	}

	if queryTablesNeedsMigrate || dataTablesNeedsMigrate {
		// rebuild query tables
		log.Info().Msgf("rebuilding query tables")
		if err := rebuild(ctx, log, d); err != nil {
			return errors.Wrap(err, "rebuild query tables error")
		}

		// populate db version
		err = d.Do(ctx, func(tx *sql.Tx) error {
			if err := setVersion(tx, d, queryTablesVersionTableName, d.QueryTablesVersion()); err != nil {
				return errors.WithStack(err)
			}
			return nil
		})
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}
