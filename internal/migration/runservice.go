package migration

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	idb "agola.io/agola/internal/db"
	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/lock"
	oldrstypes "agola.io/agola/internal/migration/runservice/types"
	ndb "agola.io/agola/internal/services/runservice/db"
	"agola.io/agola/internal/sql"
	"agola.io/agola/services/runservice/types"

	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog/log"
)

func MigrateRunService(ctx context.Context, r io.Reader, w io.Writer) error {
	ll := lock.NewLocalLocks()
	lf := lock.NewLocalLockFactory(ll)

	dir, err := ioutil.TempDir("", "agolamigration")
	if err != nil {
		return errors.Wrap(err, "new db error")
	}
	newDBPath := filepath.Join(dir, "newdb")
	os.RemoveAll(newDBPath)

	newsdb, err := sql.NewDB(sql.Sqlite3, newDBPath)
	if err != nil {
		return errors.Wrap(err, "new db error")
	}
	defer newsdb.Close()

	newd, err := ndb.NewDB(log.Logger, newsdb)
	if err != nil {
		return errors.Wrap(err, "new db error")
	}

	if err := idb.Setup(ctx, log.Logger, newd, lf); err != nil {
		return errors.Wrap(err, "create db error")
	}

	br := bufio.NewReader(r)
	dec := json.NewDecoder(br)

	// we are saving run ids in memory for querying. Could use a db if this needs too much memory
	oldRunsNewIDs := map[string]string{}

	newTx, err := newsdb.NewTx(ctx)
	if err != nil {
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

			run := types.NewRun()
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

			if err := newd.InsertRun(newTx, run); err != nil {
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

			runConfig := types.NewRunConfig()
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

			if err := newd.InsertRunConfig(newTx, runConfig); err != nil {
				return errors.WithStack(err)
			}

			// set run.RunConfigID now that we know the runConfig ID
			run, err := newd.GetRun(newTx, runID)
			if err != nil {
				return errors.WithStack(err)
			}
			if run == nil {
				return errors.Errorf("no run with id %s", runID)
			}
			run.RunConfigID = runConfig.ID
			if err := newd.UpdateRun(newTx, run); err != nil {
				return errors.WithStack(err)
			}

		case "runcounter":
			var oldRunCounter uint64

			if err := json.Unmarshal(de.Data, &oldRunCounter); err != nil {
				return errors.WithStack(err)
			}

			log.Debug().Msgf("oldRunCounter: %d", oldRunCounter)

			runCounter := types.NewRunCounter(de.ID)
			runCounter.Value = oldRunCounter

			if err := newd.InsertRunCounter(newTx, runCounter); err != nil {
				return errors.WithStack(err)
			}

		default:
			return errors.Errorf("unknown data type %q", de.DataType)
		}
	}

	// Generate run sequence
	runSequence := types.NewSequence(types.SequenceTypeRun)
	runSequence.Value = curNewRunSequence
	if err := newd.InsertSequence(newTx, runSequence); err != nil {
		return errors.WithStack(err)
	}

	if err := newTx.Commit(); err != nil {
		return errors.WithStack(err)
	}

	// Export new version
	if err := idb.Export(ctx, log.Logger, newd, w); err != nil {
		return errors.Wrap(err, "export db error")
	}

	return nil
}
