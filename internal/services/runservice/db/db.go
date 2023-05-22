package db

import (
	"context"
	stdsql "database/sql"
	"strings"

	sq "github.com/huandu/go-sqlbuilder"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/runservice/db/objects"
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/services/runservice/types"
)

//go:generate ../../../../tools/bin/dbgenerator -type db -component runservice

type DB struct {
	log zerolog.Logger
	sdb *sql.DB
}

func NewDB(log zerolog.Logger, sdb *sql.DB) (*DB, error) {
	return &DB{
		log: log,
		sdb: sdb,
	}, nil
}

func (d *DB) DBType() sql.Type {
	return d.sdb.Type()
}

func (d *DB) Do(ctx context.Context, f func(tx *sql.Tx) error) error {
	return errors.WithStack(d.sdb.Do(ctx, f))
}

func (d *DB) ObjectsInfo() []sqlg.ObjectInfo {
	return objects.ObjectsInfo
}

func (d *DB) Flavor() sq.Flavor {
	switch d.sdb.Type() {
	case sql.Postgres:
		return sq.PostgreSQL
	case sql.Sqlite3:
		return sq.SQLite
	}

	return sq.PostgreSQL
}

func (d *DB) exec(tx *sql.Tx, rq sq.Builder) (stdsql.Result, error) {
	q, args := rq.BuildWithFlavor(d.Flavor())
	// d.log.Debug().Msgf("q: %s, args: %s", q, util.Dump(args))

	r, err := tx.Exec(q, args...)
	return r, errors.WithStack(err)
}

func (d *DB) query(tx *sql.Tx, rq sq.Builder) (*stdsql.Rows, error) {
	q, args := rq.BuildWithFlavor(d.Flavor())
	// d.log.Debug().Msgf("start q: %s, args: %s", q, util.Dump(args))

	r, err := tx.Query(q, args...)
	// d.log.Debug().Msgf("end q: %s, args: %s", q, util.Dump(args))
	return r, errors.WithStack(err)
}

func mustSingleRow[T any](s []*T) (*T, error) {
	if len(s) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(s) == 0 {
		return nil, nil
	}

	return s[0], nil
}

func (d *DB) GetChangeGroups(tx *sql.Tx) ([]*types.ChangeGroup, error) {
	q := changeGroupSelect()
	changeGroups, _, err := d.fetchChangeGroups(tx, q)

	return changeGroups, errors.WithStack(err)
}

func (d *DB) GetChangeGroupsByNames(tx *sql.Tx, changeGroupsNames []string) ([]*types.ChangeGroup, error) {
	if len(changeGroupsNames) == 0 {
		return nil, nil
	}

	q := changeGroupSelect()
	q.Where(q.In("name", sq.Flatten(changeGroupsNames)...))
	changeGroups, _, err := d.fetchChangeGroups(tx, q)

	return changeGroups, errors.WithStack(err)
}

func (d *DB) GetRun(tx *sql.Tx, runID string) (*types.Run, error) {
	q := runSelect()
	q.Where(q.E("run.id", runID))
	runs, _, err := d.fetchRuns(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(runs)
	return out, errors.WithStack(err)
}

func (d *DB) GetRunByGroup(tx *sql.Tx, groupPath string, runCounter uint64) (*types.Run, error) {
	q := runSelect()

	groupPath = strings.TrimSuffix(groupPath, "/")
	// search exact path or child path (add ending slash to distinguish between final group (i.e project/projectid/branch/feature and project/projectid/branch/feature02))
	q.Where(q.And(q.Or(q.E("run.run_group", groupPath), q.Like("run.run_group", groupPath+"/%")), q.E("run.counter", runCounter)))
	runs, _, err := d.fetchRuns(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(runs)
	return out, errors.WithStack(err)
}

func (d *DB) GetRuns(tx *sql.Tx, groups []string, lastRun bool, phaseFilter []types.RunPhase, resultFilter []types.RunResult, startRunSequence uint64, limit int, sortOrder types.SortOrder) ([]*types.Run, error) {
	return d.getRunsFiltered(tx, groups, lastRun, phaseFilter, resultFilter, startRunSequence, limit, sortOrder)
}

func (d *DB) getRunsFilteredQuery(phaseFilter []types.RunPhase, resultFilter []types.RunResult, groups []string, lastRun bool, startRunSequence uint64, limit int, sortOrder types.SortOrder) *sq.SelectBuilder {
	useSubquery := false
	if len(groups) > 0 && lastRun {
		useSubquery = true
	}

	q := runSelect()
	if useSubquery {
		q = sq.NewSelectBuilder().Select("max(run.sequence)").From("run")
	}

	w := []string{}
	having := []string{}
	if len(phaseFilter) > 0 {
		w = append(w, q.In("run.phase", sq.Flatten(phaseFilter)...))
	}
	if len(resultFilter) > 0 {
		w = append(w, q.In("run.result", sq.Flatten(resultFilter)...))
	}
	if startRunSequence > 0 {
		if lastRun {
			switch sortOrder {
			case types.SortOrderAsc:
				having = append(having, q.G("run.sequence", startRunSequence))
			case types.SortOrderDesc:
				having = append(having, q.L("run.sequence", startRunSequence))
			}
		} else {
			switch sortOrder {
			case types.SortOrderAsc:
				w = append(w, q.G("run.sequence", startRunSequence))
			case types.SortOrderDesc:
				w = append(w, q.L("run.sequence", startRunSequence))
			}
		}
	}
	if limit > 0 {
		q.Limit(limit)
	}

	if len(groups) > 0 {
		cond := []string{}
		for _, groupPath := range groups {
			groupPath = strings.TrimSuffix(groupPath, "/")

			// search exact path or child path (add ending slash to distinguish between final group (i.e project/projectid/branch/feature and project/projectid/branch/feature02))
			cond = append(cond, q.E("run.run_group", groupPath), q.Like("run.run_group", groupPath+"/%"))
		}
		w = append(w, q.Or(cond...))

		if lastRun {
			q.GroupBy("run.run_group")
		}
	}

	q.Where(w...)
	q.Having(having...)

	if useSubquery {
		sq := runSelect()
		sq.Where(sq.In("run.sequence", q))

		switch sortOrder {
		case types.SortOrderAsc:
			sq.OrderBy("run.sequence").Asc()
		case types.SortOrderDesc:
			sq.OrderBy("run.sequence").Desc()
		}
		return sq
	}

	switch sortOrder {
	case types.SortOrderAsc:
		q.OrderBy("run.sequence").Asc()
	case types.SortOrderDesc:
		q.OrderBy("run.sequence").Desc()
	}

	return q
}

func (d *DB) getRunsFiltered(tx *sql.Tx, groups []string, lastRun bool, phaseFilter []types.RunPhase, resultFilter []types.RunResult, startRunSequence uint64, limit int, sortOrder types.SortOrder) ([]*types.Run, error) {
	q := d.getRunsFilteredQuery(phaseFilter, resultFilter, groups, lastRun, startRunSequence, limit, sortOrder)

	runs, _, err := d.fetchRuns(tx, q)

	return runs, errors.WithStack(err)
}

func (d *DB) GetUnarchivedRuns(tx *sql.Tx) ([]*types.Run, error) {
	q := runSelect()
	q.Where(q.E("archived", false))

	runs, _, err := d.fetchRuns(tx, q)

	return runs, errors.WithStack(err)
}

func (d *DB) GetGroupRuns(tx *sql.Tx, group string, phaseFilter []types.RunPhase, resultFilter []types.RunResult, startRunCounter uint64, limit int, sortOrder types.SortOrder) ([]*types.Run, error) {
	return d.getGroupRunsFiltered(tx, group, phaseFilter, resultFilter, startRunCounter, limit, sortOrder)
}

func (d *DB) getGroupRunsFilteredQuery(phaseFilter []types.RunPhase, resultFilter []types.RunResult, groupPath string, startRunCounter uint64, limit int, sortOrder types.SortOrder, objectstorage bool) *sq.SelectBuilder {
	q := runSelect()

	switch sortOrder {
	case types.SortOrderAsc:
		q.OrderBy("run.counter").Asc()
	case types.SortOrderDesc:
		q.OrderBy("run.counter").Desc()
	}
	if len(phaseFilter) > 0 {
		q.Where(q.In("phase", sq.Flatten(phaseFilter)...))
	}
	if len(resultFilter) > 0 {
		q.Where(q.In("result", sq.Flatten(resultFilter)...))
	}
	if startRunCounter > 0 {
		switch sortOrder {
		case types.SortOrderAsc:
			q.Where(q.G("run.counter", startRunCounter))
		case types.SortOrderDesc:
			q.Where(q.L("run.counter", startRunCounter))
		}
	}
	if limit > 0 {
		q.Limit(limit)
	}

	groupPath = strings.TrimSuffix(groupPath, "/")

	// search exact path or child path (add ending slash to distinguish between final group (i.e project/projectid/branch/feature and project/projectid/branch/feature02))
	q.Where(q.Or(q.E("run.run_group", groupPath), q.Like("run.run_group", groupPath+"/%")))

	return q
}

func (d *DB) getGroupRunsFiltered(tx *sql.Tx, group string, phaseFilter []types.RunPhase, resultFilter []types.RunResult, startRunCounter uint64, limit int, sortOrder types.SortOrder) ([]*types.Run, error) {
	q := d.getGroupRunsFilteredQuery(phaseFilter, resultFilter, group, startRunCounter, limit, sortOrder, false)

	runs, _, err := d.fetchRuns(tx, q)

	return runs, errors.WithStack(err)
}

func (d *DB) GetRunConfig(tx *sql.Tx, runConfigID string) (*types.RunConfig, error) {
	q := runConfigSelect()
	q.Where(q.E("runconfig.id", runConfigID))

	runConfigs, _, err := d.fetchRunConfigs(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(runConfigs)
	return out, errors.WithStack(err)
}

func (d *DB) GetRunCounter(tx *sql.Tx, groupID string) (*types.RunCounter, error) {
	q := runCounterSelect()
	q.Where(q.E("group_id", groupID))

	runCounters, _, err := d.fetchRunCounters(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(runCounters)
	return out, errors.WithStack(err)
}

func (d *DB) NextRunCounter(tx *sql.Tx, groupID string) (uint64, error) {
	// TODO(sgotti) Postgres currently (as of v15) returns unique constraint
	// errors hiding serializable errors also if we check for the existance
	// before the insert.
	// If we have a not existing runcounter for groupid and multiple concurrent
	// transactions try to insert the new runcounter only one will succeed and
	// the others will receive a unique constraint violation error instead of a
	// serialization error and won't by retried
	// During an update of an already existing runcounter instead a serialiation
	// error will be returned.
	//
	// This is probably related to this issue with multiple unique indexes
	// https://www.postgresql.org/message-id/flat/CAGPCyEZG76zjv7S31v_xPeLNRuzj-m%3DY2GOY7PEzu7vhB%3DyQog%40mail.gmail.com

	// This is a very unprobable event. To avoid it we could wait for postgres
	// updates or use an upsert.
	runCounter, err := d.GetRunCounter(tx, groupID)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	if runCounter == nil {
		runCounter = types.NewRunCounter(tx, groupID)
	}

	runCounter.Value++

	if err := d.InsertOrUpdateRunCounter(tx, runCounter); err != nil {
		return 0, errors.WithStack(err)
	}

	return runCounter.Value, nil
}

func (d *DB) GetRunEventsFromSequence(tx *sql.Tx, startSequence uint64, limit int) ([]*types.RunEvent, error) {
	q := runEventSelect().OrderBy("sequence").Asc()
	q.Where(q.G("sequence", startSequence))

	if limit > 0 {
		q.Limit(limit)
	}

	runEvents, _, err := d.fetchRunEvents(tx, q)
	return runEvents, errors.WithStack(err)
}

func (d *DB) GetLastRunEvent(tx *sql.Tx) (*types.RunEvent, error) {
	q := runEventSelect().OrderBy("sequence").Desc().Limit(1)

	runEvents, _, err := d.fetchRunEvents(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(runEvents)
	return out, errors.WithStack(err)
}

func (d *DB) GetExecutor(tx *sql.Tx, id string) (*types.Executor, error) {
	q := executorSelect()
	q.Where(q.E("executor.id", id))

	executors, _, err := d.fetchExecutors(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(executors)
	return out, errors.WithStack(err)
}

func (d *DB) GetExecutorByExecutorID(tx *sql.Tx, executorID string) (*types.Executor, error) {
	q := executorSelect()
	q.Where(q.E("executor.executor_id", executorID))

	executors, _, err := d.fetchExecutors(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(executors)
	return out, errors.WithStack(err)
}

func (d *DB) GetExecutors(tx *sql.Tx) ([]*types.Executor, error) {
	q := executorSelect()
	executors, _, err := d.fetchExecutors(tx, q)

	return executors, errors.WithStack(err)
}

func (d *DB) GetExecutorTasks(tx *sql.Tx) ([]*types.ExecutorTask, error) {
	q := executorTaskSelect()
	executorTasks, _, err := d.fetchExecutorTasks(tx, q)

	return executorTasks, errors.WithStack(err)
}

func (d *DB) GetExecutorTask(tx *sql.Tx, executorTaskID string) (*types.ExecutorTask, error) {
	q := executorTaskSelect()
	q.Where(q.E("executortask.id", executorTaskID))

	executorTasks, _, err := d.fetchExecutorTasks(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(executorTasks)
	return out, errors.WithStack(err)
}

func (d *DB) GetExecutorTasksByExecutor(tx *sql.Tx, executorID string) ([]*types.ExecutorTask, error) {
	q := executorTaskSelect()
	q.Where(q.E("executor_id", executorID))

	executorTasks, _, err := d.fetchExecutorTasks(tx, q)

	return executorTasks, errors.WithStack(err)

}

func (d *DB) GetExecutorTasksByRun(tx *sql.Tx, runID string) ([]*types.ExecutorTask, error) {
	q := executorTaskSelect()
	q.Where(q.E("run_id", runID))

	executorTasks, _, err := d.fetchExecutorTasks(tx, q)

	return executorTasks, errors.WithStack(err)
}

func (d *DB) GetExecutorTaskByRunTask(tx *sql.Tx, runID, runTaskID string) (*types.ExecutorTask, error) {
	q := executorTaskSelect()
	q.Where(q.And(q.E("run_id", runID), q.E("run_task_id", runTaskID)))

	executorTasks, _, err := d.fetchExecutorTasks(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(executorTasks)
	return out, errors.WithStack(err)
}
