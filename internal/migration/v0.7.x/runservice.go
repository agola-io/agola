package migration

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog/log"
	"github.com/sorintlab/errors"

	dbv1 "agola.io/agola/internal/migration/destination/runservice/db"
	oldrstypes "agola.io/agola/internal/migration/v0.7.x/source/runservice/types"
	"agola.io/agola/internal/services/runservice/db"
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/lock"
	"agola.io/agola/internal/sqlg/manager"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/services/runservice/types"
)

func MigrateRunService(ctx context.Context, r io.Reader, w io.Writer) error {
	ll := lock.NewLocalLocks()
	lf := lock.NewLocalLockFactory(ll)

	dir, err := os.MkdirTemp("", "agolamigration")
	if err != nil {
		return errors.Wrap(err, "new db error")
	}
	dbPath := filepath.Join(dir, "newdb")
	os.RemoveAll(dbPath)

	sdb, err := sql.NewDB(sql.Sqlite3, dbPath)
	if err != nil {
		return errors.Wrap(err, "new db error")
	}
	defer sdb.Close()

	// Use a copy of db at version 1
	dv1, err := dbv1.NewDB(log.Logger, sdb)
	if err != nil {
		return errors.Wrap(err, "new db error")
	}

	dbmv1 := manager.NewDBManager(log.Logger, dv1, lf)

	if err := dbmv1.Setup(ctx); err != nil {
		return errors.Wrap(err, "setup db error")
	}

	if err := dbmv1.Create(ctx, dv1.DDL(), dv1.Version()); err != nil {
		return errors.Wrap(err, "create db error")
	}

	br := bufio.NewReader(r)
	dec := json.NewDecoder(br)

	// we are saving run ids in memory for querying. Could use a db if this needs too much memory
	oldRunsNewIDs := map[string]string{}

	tx, err := sdb.NewTx(ctx)
	if err != nil {
		return errors.WithStack(err)
	}

	if _, err := tx.Exec("PRAGMA defer_foreign_keys = ON"); err != nil {
		return errors.WithStack(err)
	}

	var curNewRunSequence uint64
	var prevOldRunSequence string
	for {
		var de *DataEntry

		err := dec.Decode(&de)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.WithStack(err)
		}

		switch de.DataType {
		case "run":
			var oldRun *oldrstypes.Run

			if err := json.Unmarshal(de.Data, &oldRun); err != nil {
				return errors.WithStack(err)
			}

			oldRunj, _ := json.Marshal(oldRun)
			log.Debug().Msgf("oldrun: %s", oldRunj)

			if prevOldRunSequence > oldRun.ID {
				return errors.Errorf("prev old run sequence > cur old run sequence: %s > %s", prevOldRunSequence, oldRun.ID)
			}
			prevOldRunSequence = oldRun.ID

			curNewRunSequence++

			run := types.NewRun(tx)
			run.Sequence = curNewRunSequence
			run.Name = oldRun.Name
			run.Counter = oldRun.Counter
			run.Group = oldRun.Group
			run.Annotations = oldRun.Annotations
			run.Phase = types.RunPhase(oldRun.Phase)
			run.Result = types.RunResult(oldRun.Result)
			run.Stop = oldRun.Stop
			run.Tasks = map[string]*types.RunTask{}
			run.EnqueueTime = oldRun.EnqueueTime
			run.StartTime = oldRun.StartTime
			run.EndTime = oldRun.EndTime
			run.Archived = oldRun.Archived

			if oldRun.Tasks != nil {
				if err := mapstructure.Decode(oldRun.Tasks, &run.Tasks); err != nil {
					return errors.WithStack(err)
				}
			}

			oldRunsNewIDs[oldRun.ID] = run.ID

			if err := dv1.InsertRun(tx, run); err != nil {
				return errors.WithStack(err)
			}

		case "runconfig":
			var oldRunConfig *oldrstypes.RunConfig

			if err := json.Unmarshal(de.Data, &oldRunConfig); err != nil {
				return errors.WithStack(err)
			}

			// ignore run config with not related run
			runID, ok := oldRunsNewIDs[oldRunConfig.ID]
			if !ok {
				log.Warn().Msgf("no new run for old runconfig id %s", oldRunConfig.ID)
				continue
			}

			oldRunConfigj, _ := json.Marshal(oldRunConfig)
			log.Debug().Msgf("oldRunConfig: %s", oldRunConfigj)

			runConfig := types.NewRunConfig(tx)
			runConfig.Name = oldRunConfig.Name
			runConfig.Group = oldRunConfig.Group
			runConfig.SetupErrors = oldRunConfig.SetupErrors
			runConfig.Annotations = oldRunConfig.Annotations
			runConfig.StaticEnvironment = oldRunConfig.StaticEnvironment
			runConfig.Environment = oldRunConfig.Environment
			runConfig.Tasks = map[string]*types.RunConfigTask{}
			runConfig.CacheGroup = oldRunConfig.CacheGroup

			if oldRunConfig.Tasks != nil {
				if err := mapstructure.Decode(oldRunConfig.Tasks, &runConfig.Tasks); err != nil {
					return errors.WithStack(err)
				}
			}

			if err := dv1.InsertRunConfig(tx, runConfig); err != nil {
				return errors.WithStack(err)
			}

			// set run.RunConfigID now that we know the runConfig ID
			run, err := dv1.GetRun(tx, runID)
			if err != nil {
				return errors.WithStack(err)
			}
			if run == nil {
				return errors.Errorf("no run with id %s", runID)
			}
			run.RunConfigID = runConfig.ID
			if err := dv1.UpdateRun(tx, run); err != nil {
				return errors.WithStack(err)
			}

		case "runcounter":
			var oldRunCounter uint64

			if err := json.Unmarshal(de.Data, &oldRunCounter); err != nil {
				return errors.WithStack(err)
			}

			log.Debug().Msgf("oldRunCounter: %d", oldRunCounter)

			runCounter := types.NewRunCounter(tx, de.ID)
			runCounter.Value = oldRunCounter

			if err := dv1.InsertRunCounter(tx, runCounter); err != nil {
				return errors.WithStack(err)
			}

		default:
			return errors.Errorf("unknown data type %q", de.DataType)
		}
	}

	if err := tx.Commit(); err != nil {
		return errors.WithStack(err)
	}

	// Migrate to latest version
	d, err := db.NewDB(log.Logger, sdb)
	if err != nil {
		return errors.Wrap(err, "new db error")
	}

	dbm := manager.NewDBManager(log.Logger, d, lf)

	if err := dbm.Setup(ctx); err != nil {
		return errors.Wrap(err, "setup db error")
	}

	if err := dbm.Migrate(ctx); err != nil {
		return errors.Wrap(err, "migrate db error")
	}

	// Export new version
	if err := dbm.Export(ctx, sqlg.ObjectNames(d.ObjectsInfo()), w); err != nil {
		return errors.Wrap(err, "export db error")
	}

	return nil
}
