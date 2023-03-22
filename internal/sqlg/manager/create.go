package manager

import (
	"context"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/sqlg/sql"
)

func (m *DBManager) Create(ctx context.Context, stmts []string, wantedVersion uint) error {
	curVersion, err := m.GetVersion(ctx)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := m.CheckVersion(curVersion, wantedVersion); err != nil {
		return errors.WithStack(err)
	}

	if curVersion != 0 {
		return errors.Errorf("db already populated at version %d", curVersion)
	}

	// if there's no db, populate it with the final statements
	// fast path to avoid running all migrations from start
	err = m.d.Do(ctx, func(tx *sql.Tx) error {
		for _, stmt := range stmts {
			if _, err := tx.Exec(stmt); err != nil {
				return errors.WithStack(err)
			}
		}

		if err := m.setVersion(tx, wantedVersion); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})

	return errors.WithStack(err)
}
