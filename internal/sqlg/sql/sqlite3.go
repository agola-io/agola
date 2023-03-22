//go:build cgo

package sql

import (
	"github.com/mattn/go-sqlite3"
	"github.com/sorintlab/errors"
)

func checkSqlite3RetryError(err error) bool {
	var sqerr sqlite3.Error
	if errors.As(err, &sqerr) {
		return sqerr.Code == sqlite3.ErrLocked
	}

	return false
}
