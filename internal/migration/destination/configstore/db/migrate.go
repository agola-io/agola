package db

import (
	"agola.io/agola/internal/sqlg"
)

func (d *DB) MigrateFuncs() map[uint]sqlg.MigrateFunc {
	return map[uint]sqlg.MigrateFunc{}
}
