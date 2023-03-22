//go:build !cgo

package sql

func checkSqlite3RetryError(err error) bool {
	panic("sqlite3 disabled")
}
