package runservice

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"gotest.tools/assert"

	"agola.io/agola/internal/services/runservice/db"
	"agola.io/agola/internal/services/runservice/db/objects"
	"agola.io/agola/internal/sqlg/manager"
	"agola.io/agola/internal/testutil"
)

func newSetupDBFn(log zerolog.Logger) testutil.SetupDBFn {
	return func(ctx context.Context, t *testing.T, dir string) *testutil.DBContext {
		sdb, lf, _ := testutil.CreateDB(t, log, ctx, dir)

		d, err := db.NewDB(log, sdb)
		assert.NilError(t, err, "new db error")

		dbm := manager.NewDBManager(log, d, lf)

		err = dbm.Setup(ctx)
		assert.NilError(t, err, "setup db error")

		sc := &testutil.DBContext{D: d, DBM: dbm, LF: lf}

		return sc
	}
}

var ddls = testutil.DDLS{
	1: {
		Postgres: db.DDLPostgresV1,
		Sqlite3:  db.DDLSqlite3V1,
	},
}

var importFixtures = testutil.ImportFixtures{
	1: "dbv1",
}

func TestCreate(t *testing.T) {
	log := testutil.NewLogger(t)

	testutil.TestCreate(t, objects.Version, ddls, importFixtures, newSetupDBFn(log))
}

func TestMigrate(t *testing.T) {
	log := testutil.NewLogger(t)

	testutil.TestMigrate(t, objects.Version, ddls, importFixtures, newSetupDBFn(log))
}

func TestFixtureImportExport(t *testing.T) {
	log := testutil.NewLogger(t)

	seqs := map[string]uint64{
		"run_sequence_seq":      20,
		"runevent_sequence_seq": 20,
	}

	testutil.TestImportExport(t, objects.Version, ddls, importFixtures, newSetupDBFn(log), seqs)
}
