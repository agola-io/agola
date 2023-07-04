package manager

import (
	"context"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/sqlg/sql"
)

func (m *DBManager) Migrate(ctx context.Context) error {
	return m.MigrateToVersion(ctx, m.WantedVersion())
}

func (m *DBManager) checkMigrateFunctions(newVersion uint) error {
	migrateFuncs := m.d.MigrateFuncs()

	for nextVersion := uint(2); nextVersion <= newVersion; nextVersion++ {
		_, ok := migrateFuncs[nextVersion]
		if !ok {
			return errors.Errorf("missing migrate function to version %d", nextVersion)
		}
	}

	return nil
}

func (m *DBManager) MigrateToVersion(ctx context.Context, newVersion uint) error {
	curVersion, err := m.GetVersion(ctx)
	if err != nil {
		return errors.WithStack(err)
	}

	needsMigrate, err := m.CheckMigrationRequired(curVersion, newVersion)
	if err != nil {
		return errors.WithStack(err)
	}

	if !needsMigrate {
		return nil
	}

	if err := m.checkMigrateFunctions(newVersion); err != nil {
		return errors.WithStack(err)
	}

	migrateFuncs := m.d.MigrateFuncs()
	for nextVersion := curVersion + 1; nextVersion <= newVersion; nextVersion++ {
		m.log.Info().Msgf("doing db migration from version %d to version %d", curVersion, nextVersion)
		err := m.d.Do(ctx, func(tx *sql.Tx) error {
			if err := migrateFuncs[nextVersion](tx); err != nil {
				return errors.Wrapf(err, "failed to migrate to version %d", nextVersion)
			}

			if err := m.setVersion(tx, nextVersion); err != nil {
				return errors.WithStack(err)
			}

			return nil
		})
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}
