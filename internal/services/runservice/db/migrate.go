package db

import (
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
)

func (d *DB) MigrateFuncs() map[uint]sqlg.MigrateFunc {
	return map[uint]sqlg.MigrateFunc{
		2: d.migrateV2,
	}
}

func (d *DB) migrateV2(tx *sql.Tx) error {
	var dmlGeneric = "DELETE FROM runevent"

	if _, err := tx.Exec(dmlGeneric); err != nil {
		return errors.WithStack(err)
	}

	var ddlPostgres = []string{
		"ALTER TABLE runevent ADD COLUMN run_event_type varchar NOT NULL",
		"ALTER TABLE runevent ADD COLUMN data jsonb NOT NULL",
		"ALTER TABLE runevent ADD COLUMN data_version bigint NOT NULL",
	}

	var ddlSqlite3 = []string{
		"ALTER TABLE runevent ADD COLUMN run_event_type varchar NOT NULL",
		"ALTER TABLE runevent ADD COLUMN data text NOT NULL",
		"ALTER TABLE runevent ADD COLUMN data_version bigint NOT NULL",
	}

	var stmts []string
	switch d.sdb.Type() {
	case sql.Postgres:
		stmts = ddlPostgres
	case sql.Sqlite3:
		stmts = ddlSqlite3
	}

	for _, stmt := range stmts {
		if _, err := tx.Exec(stmt); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}
