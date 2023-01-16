package tests

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

//go:generate ../../../../../tools/bin/dbgenerator -type dbfixtures -component runservice

func newSetupDBFn(log zerolog.Logger) testutil.SetupDBFn {
	return func(ctx context.Context, t *testing.T, dir string) *testutil.DBContext {
		sdb, lf, dbConnString := testutil.CreateDB(t, log, ctx, dir)

		d, err := db.NewDB(log, sdb)
		assert.NilError(t, err, "new db error")

		dbm := manager.NewDBManager(log, d, lf)

		err = dbm.Setup(ctx)
		assert.NilError(t, err, "setup db error")

		sc := &testutil.DBContext{D: d, DBM: dbm, LF: lf, DBConnString: dbConnString}

		return sc
	}
}

var migrateFixtures = testutil.DataFixtures{
	1: "dbv1.jsonc",
	2: "dbv2.jsonc",
}

func TestCreate(t *testing.T) {
	log := testutil.NewLogger(t)

	testutil.TestCreate(t, objects.Version, migrateFixtures, newSetupDBFn(log))
}

func TestMigrate(t *testing.T) {
	log := testutil.NewLogger(t)

	testutil.TestMigrate(t, objects.Version, migrateFixtures, newSetupDBFn(log))
}
