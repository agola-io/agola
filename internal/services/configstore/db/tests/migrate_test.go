package tests

import (
	"context"
	"testing"

	"github.com/rs/zerolog"

	"agola.io/agola/internal/services/configstore/db"
	"agola.io/agola/internal/services/configstore/db/objects"
	"agola.io/agola/internal/sqlg/manager"
	"agola.io/agola/internal/testutil"
)

//go:generate ../../../../../tools/bin/dbgenerator -type dbfixtures -component configstore

func newSetupDBFn(log zerolog.Logger) testutil.SetupDBFn {
	return func(ctx context.Context, t *testing.T, dir string) *testutil.DBContext {
		sdb, lf, dbConnString := testutil.CreateDB(t, log, ctx, dir)

		d, err := db.NewDB(log, sdb)
		testutil.NilError(t, err, "new db error")

		dbm := manager.NewDBManager(log, d, lf)

		err = dbm.Setup(ctx)
		testutil.NilError(t, err, "setup db error")

		sc := &testutil.DBContext{D: d, DBM: dbm, LF: lf, DBConnString: dbConnString}

		return sc
	}
}

var importFixtures = testutil.DataFixtures{
	1: "dbv1.jsonc",
	2: "dbv2.jsonc",
	3: "dbv3.jsonc",
	4: "dbv4.jsonc",
}

func TestCreate(t *testing.T) {
	log := testutil.NewLogger(t)

	testutil.TestCreate(t, objects.Version, importFixtures, newSetupDBFn(log))
}

func TestMigrate(t *testing.T) {
	log := testutil.NewLogger(t)

	testutil.TestMigrate(t, objects.Version, importFixtures, newSetupDBFn(log))
}
