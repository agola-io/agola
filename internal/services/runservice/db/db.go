package db

import (
	"context"
	stdsql "database/sql"
	"encoding/json"
	"strings"

	idb "agola.io/agola/internal/db"
	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/services/runservice/db/objects"
	"agola.io/agola/internal/sql"
	"agola.io/agola/services/runservice/types"
	stypes "agola.io/agola/services/types"

	sq "github.com/Masterminds/squirrel"
	"github.com/rs/zerolog"
)

//go:generate ../../../../tools/bin/generators -component runservice

const (
	dataTablesVersion  = 1
	queryTablesVersion = 1
)

var dstmts = []string{
	// data tables containing object. One table per object type to make things simple.
	"create table if not exists sequence_t (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists changegroup (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists run (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists runconfig (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists runcounter (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists runevent (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists executor (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists executortask (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
}

var qstmts = []string{
	// query tables for single object types. Can be rebuilt by data tables.
	"create table if not exists sequence_t_q (id varchar, revision bigint, sequence_type varchar, data bytea, PRIMARY KEY (id))",
	"create table if not exists changegroup_q (id varchar, revision bigint, name varchar, data bytea, PRIMARY KEY (id))",
	"create table if not exists run_q (id varchar, revision bigint, grouppath varchar, sequence bigint, counter bigint, phase varchar, result varchar, archived boolean, data bytea, PRIMARY KEY (id))",
	"create table if not exists runconfig_q (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists runcounter_q (id varchar, revision bigint, groupid varchar, data bytea, PRIMARY KEY (id))",
	"create table if not exists runevent_q (id varchar, revision bigint, sequence bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists executor_q (id varchar, revision bigint, executor_id varchar, data bytea, PRIMARY KEY (id))",
	"create table if not exists executortask_q (id varchar, revision bigint, executor_id varchar, run_id varchar, runtask_id varchar, data bytea, PRIMARY KEY (id))",
}

// denormalized tables for querying, can be rebuilt by query tables.
// TODO(sgotti) currently not needed

var sb = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

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

func (d *DB) Do(ctx context.Context, f func(tx *sql.Tx) error) error {
	return errors.WithStack(d.sdb.Do(ctx, f))
}

func (d *DB) Exec(tx *sql.Tx, rq sq.Sqlizer) (stdsql.Result, error) {
	return d.exec(tx, rq)
}

func (d *DB) Query(tx *sql.Tx, rq sq.Sqlizer) (*stdsql.Rows, error) {
	return d.query(tx, rq)
}

func (d *DB) DataTablesVersion() uint  { return dataTablesVersion }
func (d *DB) QueryTablesVersion() uint { return queryTablesVersion }

func (d *DB) DTablesStatements() []string {
	return dstmts
}

func (d *DB) QTablesStatements() []string {
	return qstmts
}

func (d *DB) ObjectsInfo() []idb.ObjectInfo {
	return objects.ObjectsInfo
}

func (d *DB) exec(tx *sql.Tx, rq sq.Sqlizer) (stdsql.Result, error) {
	q, args, err := rq.ToSql()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to build query")
	}
	// d.log.Debug().Msgf("q: %s, args: %s", q, util.Dump(args))

	r, err := tx.Exec(q, args...)
	return r, errors.WithStack(err)
}

func (d *DB) query(tx *sql.Tx, rq sq.Sqlizer) (*stdsql.Rows, error) {
	q, args, err := rq.ToSql()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to build query")
	}
	// d.log.Debug().Msgf("q: %s, args: %s", q, util.Dump(args))

	r, err := tx.Query(q, args...)
	return r, errors.WithStack(err)
}

func (d *DB) UnmarshalObject(data []byte) (stypes.Object, error) {
	var om stypes.TypeMeta
	if err := json.Unmarshal(data, &om); err != nil {
		return nil, errors.WithStack(err)
	}

	var obj stypes.Object

	switch om.Kind {
	case types.SequenceKind:
		obj = &types.Sequence{}
	case types.ChangeGroupKind:
		obj = &types.ChangeGroup{}
	case types.RunKind:
		obj = &types.Run{}
	case types.RunConfigKind:
		obj = &types.RunConfig{}
	case types.RunCounterKind:
		obj = &types.RunCounter{}
	case types.RunEventKind:
		obj = &types.RunEvent{}
	case types.ExecutorKind:
		obj = &types.Executor{}
	case types.ExecutorTaskKind:
		obj = &types.ExecutorTask{}
	default:
		panic(errors.Errorf("unknown object kind %q", om.Kind))
	}

	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, errors.WithStack(err)
	}

	return obj, nil
}

func (d *DB) InsertRawObject(tx *sql.Tx, obj stypes.Object) ([]byte, error) {
	switch obj.GetKind() {
	case types.SequenceKind:
		return d.insertRawSequenceData(tx, obj.(*types.Sequence))
	case types.ChangeGroupKind:
		return d.insertRawChangeGroupData(tx, obj.(*types.ChangeGroup))
	case types.RunKind:
		return d.insertRawRunData(tx, obj.(*types.Run))
	case types.RunConfigKind:
		return d.insertRawRunConfigData(tx, obj.(*types.RunConfig))
	case types.RunCounterKind:
		return d.insertRawRunCounterData(tx, obj.(*types.RunCounter))
	case types.RunEventKind:
		return d.insertRawRunEventData(tx, obj.(*types.RunEvent))
	case types.ExecutorKind:
		return d.insertRawExecutorData(tx, obj.(*types.Executor))
	case types.ExecutorTaskKind:
		return d.insertRawExecutorTaskData(tx, obj.(*types.ExecutorTask))
	default:
		panic(errors.Errorf("unknown object kind %q", obj.GetKind()))
	}
}

func (d *DB) GetSequence(tx *sql.Tx, sequenceType types.SequenceType) (*types.Sequence, error) {
	q := sequenceQSelect.Where(sq.Eq{"sequence_type": sequenceType})
	sequences, _, err := d.fetchSequences(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(sequences) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(sequences) == 0 {
		return nil, nil
	}

	return sequences[0], nil
}

// TODO(sgotti) our sequence implementation doesn't rely on specific database
// features and is a standard object. This means that it'll be tied to the
// serializable transaction requirements basically making every transaction
// calling NextSequence really serializable (only one tx at a time).
// As a note Postgres native sequences, also with serializable transaction
// isolation, relax this constraint to permit real concurrent transactions at
// the cost of having gaps inside sequences (not an issue for us).
func (d *DB) NextSequence(tx *sql.Tx, sequenceType types.SequenceType) (uint64, error) {
	seq, err := d.GetSequence(tx, sequenceType)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	if seq == nil {
		seq = types.NewSequence(sequenceType)
	}

	seq.Value++

	if err := d.InsertOrUpdateSequence(tx, seq); err != nil {
		return 0, errors.WithStack(err)
	}

	return seq.Value, nil
}

func (d *DB) GetChangeGroups(tx *sql.Tx) ([]*types.ChangeGroup, error) {
	q := changeGroupQSelect
	changeGroups, _, err := d.fetchChangeGroups(tx, q)

	return changeGroups, errors.WithStack(err)
}

func (d *DB) GetChangeGroupsByNames(tx *sql.Tx, changeGroupsNames []string) ([]*types.ChangeGroup, error) {
	q := changeGroupQSelect.Where(sq.Eq{"name": changeGroupsNames})
	changeGroups, _, err := d.fetchChangeGroups(tx, q)

	return changeGroups, errors.WithStack(err)
}

func (d *DB) GetRun(tx *sql.Tx, runID string) (*types.Run, error) {
	q := runQSelect.Where(sq.Eq{"run_q.id": runID})
	runs, _, err := d.fetchRuns(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(runs) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(runs) == 0 {
		return nil, nil
	}

	return runs[0], nil
}

func (d *DB) GetRunByGroup(tx *sql.Tx, groupPath string, runCounter uint64) (*types.Run, error) {
	if !strings.HasSuffix(groupPath, "/") {
		groupPath += "/"
	}

	q := runQSelect.Where(sq.And{sq.Like{"run_q.grouppath": groupPath + "%"}, sq.Eq{"run_q.counter": runCounter}})
	runs, _, err := d.fetchRuns(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(runs) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(runs) == 0 {
		return nil, nil
	}

	return runs[0], nil
}

func (d *DB) GetRuns(tx *sql.Tx, groups []string, lastRun bool, phaseFilter []types.RunPhase, resultFilter []types.RunResult, startRunSequence uint64, limit int, sortOrder types.SortOrder) ([]*types.Run, error) {
	return d.getRunsFiltered(tx, groups, lastRun, phaseFilter, resultFilter, startRunSequence, limit, sortOrder)
}

func (d *DB) getRunsFilteredQuery(phaseFilter []types.RunPhase, resultFilter []types.RunResult, groups []string, lastRun bool, startRunSequence uint64, limit int, sortOrder types.SortOrder) sq.SelectBuilder {
	q := runQSelect
	if len(groups) > 0 && lastRun {
		q = q.Columns("max(run_q.sequence)")
	}

	switch sortOrder {
	case types.SortOrderAsc:
		q = q.OrderBy("run_q.sequence asc")
	case types.SortOrderDesc:
		q = q.OrderBy("run_q.sequence desc")
	}
	if len(phaseFilter) > 0 {
		q = q.Where(sq.Eq{"phase": phaseFilter})
	}
	if len(resultFilter) > 0 {
		q = q.Where(sq.Eq{"result": resultFilter})
	}
	if startRunSequence > 0 {
		if lastRun {
			switch sortOrder {
			case types.SortOrderAsc:
				q = q.Having(sq.Gt{"run_q.sequence": startRunSequence})
			case types.SortOrderDesc:
				q = q.Having(sq.Lt{"run_q.sequence": startRunSequence})
			}
		} else {
			switch sortOrder {
			case types.SortOrderAsc:
				q = q.Where(sq.Gt{"run_q.sequence": startRunSequence})
			case types.SortOrderDesc:
				q = q.Where(sq.Lt{"run_q.sequence": startRunSequence})
			}
		}
	}
	if limit > 0 {
		q = q.Limit(uint64(limit))
	}

	if len(groups) > 0 {
		cond := sq.Or{}
		for _, groupPath := range groups {
			// add ending slash to distinguish between final group (i.e project/projectid/branch/feature and project/projectid/branch/feature02)
			if !strings.HasSuffix(groupPath, "/") {
				groupPath += "/"
			}

			cond = append(cond, sq.Like{"run_q.grouppath": groupPath + "%"})
		}
		q = q.Where(sq.Or{cond})
		if lastRun {
			q = q.GroupBy("run_q.grouppath")
		}
	}

	return q
}

func (d *DB) getRunsFiltered(tx *sql.Tx, groups []string, lastRun bool, phaseFilter []types.RunPhase, resultFilter []types.RunResult, startRunSequence uint64, limit int, sortOrder types.SortOrder) ([]*types.Run, error) {
	q := d.getRunsFilteredQuery(phaseFilter, resultFilter, groups, lastRun, startRunSequence, limit, sortOrder)

	runs, _, err := d.fetchRuns(tx, q)

	return runs, errors.WithStack(err)
}

func (d *DB) GetUnarchivedRuns(tx *sql.Tx) ([]*types.Run, error) {
	q := runQSelect.Where(sq.Eq{"archived": false})
	runs, _, err := d.fetchRuns(tx, q)

	return runs, errors.WithStack(err)
}

func (d *DB) GetGroupRuns(tx *sql.Tx, group string, phaseFilter []types.RunPhase, resultFilter []types.RunResult, startRunCounter uint64, limit int, sortOrder types.SortOrder) ([]*types.Run, error) {
	return d.getGroupRunsFiltered(tx, group, phaseFilter, resultFilter, startRunCounter, limit, sortOrder)
}

func (d *DB) getGroupRunsFilteredQuery(phaseFilter []types.RunPhase, resultFilter []types.RunResult, groupPath string, startRunCounter uint64, limit int, sortOrder types.SortOrder, objectstorage bool) sq.SelectBuilder {
	q := runQSelect

	switch sortOrder {
	case types.SortOrderAsc:
		q = q.OrderBy("run_q.counter asc")
	case types.SortOrderDesc:
		q = q.OrderBy("run_q.counter desc")
	}
	if len(phaseFilter) > 0 {
		q = q.Where(sq.Eq{"phase": phaseFilter})
	}
	if len(resultFilter) > 0 {
		q = q.Where(sq.Eq{"result": resultFilter})
	}
	if startRunCounter > 0 {
		switch sortOrder {
		case types.SortOrderAsc:
			q = q.Where(sq.Gt{"run_q.counter": startRunCounter})
		case types.SortOrderDesc:
			q = q.Where(sq.Lt{"run_q.counter": startRunCounter})
		}
	}
	if limit > 0 {
		q = q.Limit(uint64(limit))
	}

	// add ending slash to distinguish between final group (i.e project/projectid/branch/feature and project/projectid/branch/feature02)
	if !strings.HasSuffix(groupPath, "/") {
		groupPath += "/"
	}

	q = q.Where(sq.Like{"run_q.grouppath": groupPath + "%"})

	return q
}

func (d *DB) getGroupRunsFiltered(tx *sql.Tx, group string, phaseFilter []types.RunPhase, resultFilter []types.RunResult, startRunCounter uint64, limit int, sortOrder types.SortOrder) ([]*types.Run, error) {
	q := d.getGroupRunsFilteredQuery(phaseFilter, resultFilter, group, startRunCounter, limit, sortOrder, false)

	runs, _, err := d.fetchRuns(tx, q)

	return runs, errors.WithStack(err)
}

func (d *DB) GetRunConfig(tx *sql.Tx, runConfigID string) (*types.RunConfig, error) {
	q := runConfigQSelect.Where(sq.Eq{"runconfig_q.id": runConfigID})
	runConfigs, _, err := d.fetchRunConfigs(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(runConfigs) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(runConfigs) == 0 {
		return nil, nil
	}

	return runConfigs[0], nil
}

func (d *DB) GetRunCounter(tx *sql.Tx, groupID string) (*types.RunCounter, error) {
	q := runCounterQSelect.Where(sq.Eq{"groupid": groupID})
	runCounters, _, err := d.fetchRunCounters(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(runCounters) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(runCounters) == 0 {
		return nil, nil
	}

	return runCounters[0], nil
}

func (d *DB) NextRunCounter(tx *sql.Tx, groupID string) (uint64, error) {
	runCounter, err := d.GetRunCounter(tx, groupID)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	if runCounter == nil {
		runCounter = types.NewRunCounter(groupID)
	}

	runCounter.Value++

	if err := d.InsertOrUpdateRunCounter(tx, runCounter); err != nil {
		return 0, errors.WithStack(err)
	}

	return runCounter.Value, nil
}

func (d *DB) GetRunEventsFromSequence(tx *sql.Tx, startSequence uint64, limit int) ([]*types.RunEvent, error) {
	q := runEventQSelect.OrderBy("sequence asc").Where(sq.Gt{"sequence": startSequence})

	if limit > 0 {
		q = q.Limit(uint64(limit))
	}

	runEvents, _, err := d.fetchRunEvents(tx, q)
	return runEvents, errors.WithStack(err)
}

func (d *DB) GetLastRunEvent(tx *sql.Tx) (*types.RunEvent, error) {
	q := runEventQSelect.OrderBy("sequence desc").Limit(1)

	runEvents, _, err := d.fetchRunEvents(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(runEvents) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(runEvents) == 0 {
		return nil, nil
	}

	return runEvents[0], nil
}

func (d *DB) GetExecutor(tx *sql.Tx, id string) (*types.Executor, error) {
	q := executorQSelect.Where(sq.Eq{"executor_q.id": id})
	executors, _, err := d.fetchExecutors(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(executors) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(executors) == 0 {
		return nil, nil
	}

	return executors[0], nil
}

func (d *DB) GetExecutorByExecutorID(tx *sql.Tx, executorID string) (*types.Executor, error) {
	q := executorQSelect.Where(sq.Eq{"executor_q.executor_id": executorID})
	executors, _, err := d.fetchExecutors(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(executors) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(executors) == 0 {
		return nil, nil
	}

	return executors[0], nil
}

func (d *DB) GetExecutors(tx *sql.Tx) ([]*types.Executor, error) {
	q := executorQSelect
	executors, _, err := d.fetchExecutors(tx, q)

	return executors, errors.WithStack(err)
}

func (d *DB) GetExecutorTasks(tx *sql.Tx) ([]*types.ExecutorTask, error) {
	q := executorTaskQSelect
	executorTasks, _, err := d.fetchExecutorTasks(tx, q)

	return executorTasks, errors.WithStack(err)
}

func (d *DB) GetExecutorTask(tx *sql.Tx, executorTaskID string) (*types.ExecutorTask, error) {
	q := executorTaskQSelect.Where(sq.Eq{"executortask_q.id": executorTaskID})
	executorTasks, _, err := d.fetchExecutorTasks(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(executorTasks) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(executorTasks) == 0 {
		return nil, nil
	}

	return executorTasks[0], nil
}

func (d *DB) GetExecutorTasksByExecutor(tx *sql.Tx, executorID string) ([]*types.ExecutorTask, error) {
	q := executorTaskQSelect.Where(sq.Eq{"executor_id": executorID})
	executorTasks, _, err := d.fetchExecutorTasks(tx, q)

	return executorTasks, errors.WithStack(err)

}

func (d *DB) GetExecutorTasksByRun(tx *sql.Tx, runID string) ([]*types.ExecutorTask, error) {
	q := executorTaskQSelect.Where(sq.Eq{"run_id": runID})
	executorTasks, _, err := d.fetchExecutorTasks(tx, q)

	return executorTasks, errors.WithStack(err)
}

func (d *DB) GetExecutorTaskByRunTask(tx *sql.Tx, runID, runTaskID string) (*types.ExecutorTask, error) {
	q := executorTaskQSelect.Where(sq.Eq{"run_id": runID, "runtask_id": runTaskID})
	executorTasks, _, err := d.fetchExecutorTasks(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(executorTasks) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(executorTasks) == 0 {
		return nil, nil
	}

	return executorTasks[0], nil
}
