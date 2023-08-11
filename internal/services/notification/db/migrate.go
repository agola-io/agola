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
	var ddlPostgres = []string{
		"create table if not exists lastruneventsequence (id varchar NOT NULL, revision bigint NOT NULL, creation_time timestamptz NOT NULL, update_time timestamptz NOT NULL, value bigint NOT NULL, PRIMARY KEY (id))",
	}

	var ddlSqlite3 = []string{
		"create table if not exists lastruneventsequence (id varchar NOT NULL, revision bigint NOT NULL, creation_time timestamp NOT NULL, update_time timestamp NOT NULL, value bigint NOT NULL, PRIMARY KEY (id))",
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
