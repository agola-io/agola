package sql

import (
	"context"
	stdsql "database/sql"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sorintlab/errors"
	"gotest.tools/assert"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func SetupDB(t *testing.T, ctx context.Context, dir string) *DB {
	var dbType Type
	switch os.Getenv("DB_TYPE") {
	case "":
		dbType = Sqlite3
	case "sqlite3":
		dbType = Sqlite3
	case "postgres":
		dbType = Postgres
	default:
		t.Fatalf("unknown db type")
	}

	pgConnString := os.Getenv("PG_CONNSTRING")

	var err error
	var sdb *DB

	switch dbType {
	case Sqlite3:
		dbName := "testdb" + strconv.FormatUint(uint64(rand.Uint32()), 10)
		dbPath := filepath.Join(dir, dbName)

		sdb, err = NewDB("sqlite3", dbPath)
		assert.NilError(t, err)

	case Postgres:
		dbName := "testdb" + strconv.FormatUint(uint64(rand.Uint32()), 10)

		pgdb, err := stdsql.Open("postgres", fmt.Sprintf(pgConnString, "postgres"))
		assert.NilError(t, err)

		_, err = pgdb.Exec(fmt.Sprintf("drop database if exists %s", dbName))
		assert.NilError(t, err)

		_, err = pgdb.Exec(fmt.Sprintf("create database %s", dbName))
		assert.NilError(t, err)

		sdb, err = NewDB("postgres", fmt.Sprintf(pgConnString, dbName))
		assert.NilError(t, err)

	default:
		t.Fatalf("unknown db type")
	}

	return sdb
}

// TestPGSerializationError tests that db handles serialization errors by retrying the transaction n times and ensure that the result is the expected one
func TestPGSerializationError(t *testing.T) {
	ctx := context.Background()

	switch os.Getenv("DB_TYPE") {
	case "postgres":
	default:
		t.Skip("DB_TYPE isn't postgres")
	}

	tmpDir := t.TempDir()

	sdb := SetupDB(t, ctx, tmpDir)

	_, err := sdb.db.Exec("create table if not exists table01 (id varchar, data varchar, PRIMARY KEY (id))")
	assert.NilError(t, err)

	txErrors := []error{}

	fetchEntriesFn := func(tx *Tx) ([]string, error) {
		rows, err := tx.Query("select * from table01")
		if err != nil {
			return nil, errors.WithStack(err)
		}
		defer rows.Close()

		entries := []string{}
		for rows.Next() {
			var id string
			var data string
			if err := rows.Scan(&id, &data); err != nil {
				return nil, errors.Wrap(err, "failed to scan rows")
			}
			entries = append(entries, id)
		}
		if err := rows.Err(); err != nil {
			return nil, errors.WithStack(err)
		}

		return entries, nil
	}

	// start a transaction, wait on channel to start, get all entries and add an entry only if there're no entries.
	insertEntryFn := func(txCount *uint32, ch chan struct{}) error {
		return sdb.Do(ctx, func(tx *Tx) error {
			atomic.AddUint32(txCount, 1)

			<-ch
			entries, err := fetchEntriesFn(tx)
			if err != nil {
				return errors.WithStack(err)
			}

			if len(entries) != 0 {
				return nil
			}

			if _, err := tx.Exec(`insert into table01 values ('01', 'data')`); err != nil {
				return errors.WithStack(err)
			}

			return nil
		})
	}

	// start two goroutines executing the transaction. One should fail at least
	// one time due to serialization error
	n := 2
	var wg sync.WaitGroup
	wg.Add(n)
	var txCount uint32

	ch := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			err := insertEntryFn(&txCount, ch)
			if err != nil {
				txErrors = append(txErrors, err)
			}
			wg.Done()
		}()
	}

	close(ch)

	wg.Wait()
	assert.Assert(t, len(txErrors) == 0)

	var entries []string
	err = sdb.Do(ctx, func(tx *Tx) error {
		var err error
		entries, err = fetchEntriesFn(tx)
		return errors.WithStack(err)
	})
	assert.NilError(t, err)

	assert.Assert(t, len(entries) == 1, "entries = %d", len(entries))

	// there must be at least one retried tx, so at least n + 1 transactions
	assert.Assert(t, txCount >= uint32(n), "txCount = %d", txCount)
}
