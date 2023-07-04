package common

import (
	"context"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/sqlg/manager"
)

func SetupDB(ctx context.Context, dbm *manager.DBManager) error {
	wantedVersion := dbm.WantedVersion()

	if err := dbm.Lock(ctx); err != nil {
		return errors.WithStack(err)
	}
	defer func() { _ = dbm.Unlock() }()

	if err := dbm.Setup(ctx); err != nil {
		return errors.Wrap(err, "setup db error")
	}

	curDBVersion, err := dbm.GetVersion(ctx)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := dbm.CheckVersion(curDBVersion, wantedVersion); err != nil {
		return errors.WithStack(err)
	}

	if curDBVersion == 0 {
		if err := dbm.Create(ctx, dbm.DDL(), wantedVersion); err != nil {
			return errors.Wrap(err, "create db error")
		}
	} else {
		migrationRequired, err := dbm.CheckMigrationRequired(curDBVersion, wantedVersion)
		if err != nil {
			return errors.WithStack(err)
		}
		if migrationRequired {
			return errors.Errorf("db requires migration, current version: %d, wanted version: %d", curDBVersion, wantedVersion)
		}
	}

	return nil
}
