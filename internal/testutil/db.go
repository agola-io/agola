package testutil

import (
	"bytes"
	"context"
	stdsql "database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"

	atlassqlclient "ariga.io/atlas/sql/sqlclient"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"
	"gotest.tools/assert"
	"muzzammil.xyz/jsonc"

	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/lock"
	"agola.io/agola/internal/sqlg/manager"
	"agola.io/agola/internal/sqlg/sql"

	_ "ariga.io/atlas/sql/postgres"
	_ "ariga.io/atlas/sql/postgres/postgrescheck"
	_ "ariga.io/atlas/sql/sqlite"
	_ "ariga.io/atlas/sql/sqlite/sqlitecheck"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func DBType(t *testing.T) sql.Type {
	var dbType sql.Type
	switch os.Getenv("DB_TYPE") {
	case "":
		fallthrough
	case "sqlite3":
		dbType = sql.Sqlite3
	case "postgres":
		dbType = sql.Postgres
	default:
		t.Fatalf("unknown db type")
	}

	return dbType
}

func CreateDB(t *testing.T, log zerolog.Logger, ctx context.Context, dir string) (*sql.DB, lock.LockFactory, string) {
	dbType := DBType(t)

	return CreateDBWithType(t, log, ctx, dir, dbType)
}

func CreateDBWithType(t *testing.T, log zerolog.Logger, ctx context.Context, dir string, dbType sql.Type) (*sql.DB, lock.LockFactory, string) {
	pgConnString := os.Getenv("PG_CONNSTRING")

	var err error
	var sdb *sql.DB
	var connString string

	switch dbType {
	case sql.Sqlite3:
		dbName := "testdb" + strconv.FormatUint(uint64(rand.Uint32()), 10)
		connString = filepath.Join(dir, dbName)

		sdb, err = sql.NewDB("sqlite3", connString)
		assert.NilError(t, err)

	case sql.Postgres:
		dbName := "testdb" + strconv.FormatUint(uint64(rand.Uint32()), 10)
		connString = fmt.Sprintf(pgConnString, dbName)

		pgdb, err := stdsql.Open("postgres", fmt.Sprintf(pgConnString, "postgres"))
		assert.NilError(t, err)

		_, err = pgdb.Exec(fmt.Sprintf("drop database if exists %s", dbName))
		assert.NilError(t, err)

		_, err = pgdb.Exec(fmt.Sprintf("create database %s", dbName))
		assert.NilError(t, err)

		sdb, err = sql.NewDB("postgres", connString)
		assert.NilError(t, err)

	default:
		t.Fatalf("unknown db type")
	}

	var lf lock.LockFactory
	switch dbType {
	case sql.Sqlite3:
		ll := lock.NewLocalLocks()
		lf = lock.NewLocalLockFactory(ll)
	case sql.Postgres:
		lf = lock.NewPGLockFactory(sdb)
	default:
		t.Fatalf("unknown type %q", dbType)
	}

	return sdb, lf, connString
}

type DBContext struct {
	D            manager.DB
	DBM          *manager.DBManager
	LF           lock.LockFactory
	DBConnString string
}

func (c *DBContext) AtlasConnString() string {
	switch c.D.DBType() {
	case sql.Postgres:
		return c.DBConnString
	case sql.Sqlite3:
		return fmt.Sprintf("sqlite://%s", c.DBConnString)
	}

	return ""
}

type SetupDBFn func(ctx context.Context, t *testing.T, dir string) *DBContext

type DDL struct {
	Postgres []string
	Sqlite3  []string
}

type DDLS map[uint]DDL

type ImportFixtures map[uint]string

func TestCreate(t *testing.T, lastVersion uint, ddls DDLS, fixtures ImportFixtures, setupDBFn SetupDBFn) {
	startVersion := uint(1)

	for createVersion := startVersion; createVersion <= lastVersion; createVersion++ {
		t.Run(fmt.Sprintf("create db at version %d", createVersion), func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			dc := setupDBFn(ctx, t, dir)

			createFixtureFile, ok := fixtures[createVersion]
			if !ok {
				t.Fatalf("missing fixture for db version %d", createVersion)
			}
			createFixture, err := os.ReadFile(filepath.Join("fixtures", createFixtureFile))
			assert.NilError(t, err)
			createFixture = jsonc.ToJSON(createFixture)

			ddl := ddls[createVersion]

			var stmts []string
			switch dc.D.DBType() {
			case sql.Postgres:
				stmts = ddl.Postgres
			case sql.Sqlite3:
				stmts = ddl.Sqlite3
			}

			err = dc.DBM.Setup(ctx)
			assert.NilError(t, err, "setup db error")

			err = dc.DBM.Create(ctx, stmts, createVersion)
			assert.NilError(t, err)

			err = dc.DBM.Import(ctx, bytes.NewBuffer(createFixture))
			assert.NilError(t, err)
		})
	}
}

func TestMigrate(t *testing.T, lastVersion uint, ddls DDLS, fixtures ImportFixtures, setupDBFn SetupDBFn) {
	startVersion := uint(1)
	// check all versions are available
	for createVersion := startVersion; createVersion < lastVersion; createVersion++ {
		if _, ok := ddls[createVersion]; !ok {
			t.Fatalf("missing test ddl for version %d", createVersion)
		}
		if _, ok := fixtures[createVersion]; !ok {
			t.Fatalf("missing test import fixtures for version %d", createVersion)
		}
	}

	for createVersion := startVersion; createVersion < lastVersion; createVersion++ {
		for migrateVersion := createVersion + 1; migrateVersion <= lastVersion; migrateVersion++ {
			t.Run(fmt.Sprintf("migrate db from version %d to version %d", createVersion, migrateVersion), func(t *testing.T) {
				dir := t.TempDir()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				// create db at migrate version. For diff from migrated version.
				createDC := setupDBFn(ctx, t, dir)

				createFixtureFile, ok := fixtures[migrateVersion]
				if !ok {
					t.Fatalf("missing fixture for db version %d", migrateVersion)
				}
				createFixture, err := os.ReadFile(filepath.Join("fixtures", createFixtureFile))
				assert.NilError(t, err)
				createFixture = jsonc.ToJSON(createFixture)

				createDDL := ddls[migrateVersion]

				var createStmts []string
				switch createDC.D.DBType() {
				case sql.Postgres:
					createStmts = createDDL.Postgres
				case sql.Sqlite3:
					createStmts = createDDL.Sqlite3
				}

				err = createDC.DBM.Setup(ctx)
				assert.NilError(t, err, "setup db error")

				err = createDC.DBM.Create(ctx, createStmts, migrateVersion)
				assert.NilError(t, err)

				err = createDC.DBM.Import(ctx, bytes.NewBuffer(createFixture))
				assert.NilError(t, err)

				// create db at create version to be migrated.
				dc := setupDBFn(ctx, t, dir)
				fixtureFile, ok := fixtures[createVersion]
				if !ok {
					t.Fatalf("missing fixture for db version %d", createVersion)
				}
				fixture, err := os.ReadFile(filepath.Join("fixtures", fixtureFile))
				assert.NilError(t, err)
				fixture = jsonc.ToJSON(fixture)

				ddl := ddls[createVersion]

				var stmts []string
				switch dc.D.DBType() {
				case sql.Postgres:
					stmts = ddl.Postgres
				case sql.Sqlite3:
					stmts = ddl.Sqlite3
				}

				err = dc.DBM.Setup(ctx)
				assert.NilError(t, err, "setup db error")

				err = dc.DBM.Create(ctx, stmts, createVersion)
				assert.NilError(t, err)

				err = dc.DBM.Import(ctx, bytes.NewBuffer(fixture))
				assert.NilError(t, err)

				err = dc.DBM.MigrateToVersion(ctx, migrateVersion)
				assert.NilError(t, err)

				// Diff created and migrated schema
				createAtlasClient, err := atlassqlclient.Open(ctx, createDC.AtlasConnString())
				assert.NilError(t, err)

				atlasClient, err := atlassqlclient.Open(ctx, dc.AtlasConnString())
				assert.NilError(t, err)

				createRealm, err := createAtlasClient.InspectRealm(ctx, nil)
				assert.NilError(t, err)

				realm, err := atlasClient.InspectRealm(ctx, nil)
				assert.NilError(t, err)

				diff, err := atlasClient.RealmDiff(createRealm, realm)
				assert.NilError(t, err)

				assert.Assert(t, len(diff) == 0, "schema of db created at version %d and db migrated from version %d to version %d is different:\n %s", migrateVersion, createVersion, migrateVersion, diff)

				createExport := &bytes.Buffer{}
				export := &bytes.Buffer{}

				err = createDC.DBM.Export(ctx, sqlg.ObjectNames(createDC.D.ObjectsInfo()), createExport)
				assert.NilError(t, err)

				err = dc.DBM.Export(ctx, sqlg.ObjectNames(dc.D.ObjectsInfo()), export)
				assert.NilError(t, err)

				// Diff database data
				createExportMap := decodeExport(t, dc.D, createExport.Bytes())
				exportMap := decodeExport(t, dc.D, export.Bytes())

				// Since postgres has microsecond time precision while go has nanosecond time precision we should check times with a microsecond margin
				assert.DeepEqual(t, createExportMap, exportMap, cmpopts.EquateApproxTime(1*time.Microsecond))
			})
		}
	}
}

func decodeExport(t *testing.T, d manager.DB, export []byte) []any {
	dec := json.NewDecoder(bytes.NewReader(export))

	objs := []any{}

	for {
		var jobj json.RawMessage

		err := dec.Decode(&jobj)
		if errors.Is(err, io.EOF) {
			break
		}
		assert.NilError(t, err)

		obj, err := d.UnmarshalExportObject(jobj)
		assert.NilError(t, err)

		objs = append(objs, obj)
	}

	// sort objects by id
	sort.Slice(objs, func(i, j int) bool {
		o1 := objs[i].(sqlg.Object)
		o2 := objs[j].(sqlg.Object)
		return o1.GetID() < o2.GetID()
	})

	return objs
}

func TestImportExport(t *testing.T, lastVersion uint, ddls DDLS, fixtures ImportFixtures, setupDBFn SetupDBFn, seqs map[string]uint64) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ddl := ddls[lastVersion]

	dc := setupDBFn(ctx, t, dir)

	fixtureFile, ok := fixtures[lastVersion]
	if !ok {
		t.Fatalf("missing fixture for db version %d", lastVersion)
	}

	fixture, err := os.ReadFile(filepath.Join("fixtures", fixtureFile))
	assert.NilError(t, err)

	var stmts []string
	switch dc.D.DBType() {
	case sql.Postgres:
		stmts = ddl.Postgres
	case sql.Sqlite3:
		stmts = ddl.Sqlite3
	}

	err = dc.DBM.Create(ctx, stmts, 1)
	assert.NilError(t, err)

	err = dc.DBM.Import(ctx, bytes.NewBuffer(fixture))
	assert.NilError(t, err)

	// check sequences
	curSeqs := map[string]uint64{}

	err = dc.D.Do(ctx, func(tx *sql.Tx) error {
		for _, seq := range dc.D.Sequences() {
			var err error

			seqValue, err := dc.D.GetSequence(tx, seq)
			if err != nil {
				return errors.WithStack(err)
			}

			curSeqs[seq] = seqValue
		}

		return nil
	})
	assert.NilError(t, err)

	assert.DeepEqual(t, curSeqs, seqs)

	export := &bytes.Buffer{}

	err = dc.DBM.Export(ctx, sqlg.ObjectNames(dc.D.ObjectsInfo()), export)
	assert.NilError(t, err)

	exportMap := decodeExport(t, dc.D, export.Bytes())
	fixturesMap := decodeExport(t, dc.D, fixture)

	// Since postgres has microsecond time precision while go has nanosecond time precision we should check times with a microsecond margin
	assert.DeepEqual(t, fixturesMap, exportMap, cmpopts.EquateApproxTime(1*time.Microsecond))
}
