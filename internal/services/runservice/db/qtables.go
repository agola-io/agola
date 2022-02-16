package db

import (
	"strings"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/sql"
	"agola.io/agola/services/runservice/types"
	stypes "agola.io/agola/services/types"

	sq "github.com/Masterminds/squirrel"
)

var (
	// TODO(sgotti) generate also these ones
	// TODO(sgotti) currently we are duplicating revision and data in the query tables. Another solution will be to join with the data table (what about performances?)
	sequenceQSelect = sb.Select("sequence_t_q.id", "sequence_t_q.revision", "sequence_t_q.data").From("sequence_t_q")
	sequenceQInsert = func(id string, revision uint64, sequenceType types.SequenceType, data []byte) sq.InsertBuilder {
		return sb.Insert("sequence_t_q").Columns("id", "revision", "sequence_type", "data").Values(id, revision, sequenceType, data)
	}
	sequenceQUpdate = func(id string, revision uint64, sequenceType types.SequenceType, data []byte) sq.UpdateBuilder {
		return sb.Update("sequence_t_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "sequence_type": sequenceType, "data": data}).Where(sq.Eq{"id": id})
	}

	changeGroupQSelect = sb.Select("changegroup_q.id", "changegroup_q.revision", "changegroup_q.data").From("changegroup_q")
	changeGroupQInsert = func(id string, revision uint64, name string, data []byte) sq.InsertBuilder {
		return sb.Insert("changegroup_q").Columns("id", "revision", "name", "data").Values(id, revision, name, data)
	}
	changeGroupQUpdate = func(id string, revision uint64, name string, data []byte) sq.UpdateBuilder {
		return sb.Update("changegroup_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "name": name, "data": data}).Where(sq.Eq{"id": id})
	}

	runQSelect = sb.Select("run_q.id", "run_q.revision", "run_q.data").From("run_q")
	runQInsert = func(id string, revision uint64, groupPath string, sequence, counter uint64, phase types.RunPhase, result types.RunResult, archived bool, data []byte) sq.InsertBuilder {
		return sb.Insert("run_q").Columns("id", "revision", "grouppath", "sequence", "counter", "phase", "result", "archived", "data").Values(id, revision, groupPath, sequence, counter, phase, result, archived, data)
	}
	runQUpdate = func(id string, revision uint64, groupPath string, sequence, counter uint64, phase types.RunPhase, result types.RunResult, archived bool, data []byte) sq.UpdateBuilder {
		return sb.Update("run_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "grouppath": groupPath, "sequence": sequence, "counter": counter, "phase": phase, "result": result, "archived": archived, "data": data}).Where(sq.Eq{"id": id})
	}

	runConfigQSelect = sb.Select("runconfig_q.id", "runconfig_q.revision", "runconfig_q.data").From("runconfig_q")
	runConfigQInsert = func(id string, revision uint64, data []byte) sq.InsertBuilder {
		return sb.Insert("runconfig_q").Columns("id", "revision", "data").Values(id, revision, data)
	}
	runConfigQUpdate = func(id string, revision uint64, data []byte) sq.UpdateBuilder {
		return sb.Update("runconfig_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "data": data}).Where(sq.Eq{"id": id})
	}

	runCounterQSelect = sb.Select("runcounter_q.id", "runcounter_q.revision", "runcounter_q.data").From("runcounter_q")
	runCounterQInsert = func(id string, revision uint64, groupID string, data []byte) sq.InsertBuilder {
		return sb.Insert("runcounter_q").Columns("id", "revision", "groupid", "data").Values(id, revision, groupID, data)
	}
	runCounterQUpdate = func(id string, revision uint64, groupID string, data []byte) sq.UpdateBuilder {
		return sb.Update("runcounter_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "groupid": groupID, "data": data}).Where(sq.Eq{"id": id})
	}

	runEventQSelect = sb.Select("runevent_q.id", "runevent_q.revision", "runevent_q.data").From("runevent_q")
	runEventQInsert = func(id string, revision uint64, sequence uint64, data []byte) sq.InsertBuilder {
		return sb.Insert("runevent_q").Columns("id", "revision", "sequence", "data").Values(id, revision, sequence, data)
	}
	runEventQUpdate = func(id string, revision uint64, sequence uint64, data []byte) sq.UpdateBuilder {
		return sb.Update("runevent_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "sequence": sequence, "data": data}).Where(sq.Eq{"id": id})
	}

	executorQSelect = sb.Select("executor_q.id", "executor_q.revision", "executor_q.data").From("executor_q")
	executorQInsert = func(id string, revision uint64, executorID string, data []byte) sq.InsertBuilder {
		return sb.Insert("executor_q").Columns("id", "revision", "executor_id", "data").Values(id, revision, executorID, data)
	}
	executorQUpdate = func(id string, revision uint64, executorID string, data []byte) sq.UpdateBuilder {
		return sb.Update("executor_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "executor_id": executorID, "data": data}).Where(sq.Eq{"id": id})
	}

	executorTaskQSelect = sb.Select("executortask_q.id", "executortask_q.revision", "executortask_q.data").From("executortask_q")
	executorTaskQInsert = func(id string, revision uint64, executorID, runID, runTaskID string, data []byte) sq.InsertBuilder {
		return sb.Insert("executortask_q").Columns("id", "revision", "executor_id", "run_id", "runtask_id", "data").Values(id, revision, executorID, runID, runTaskID, data)
	}
	executorTaskQUpdate = func(id string, revision uint64, executorID, runID, runTaskID string, data []byte) sq.UpdateBuilder {
		return sb.Update("executortask_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "executor_id": executorID, "run_id": runID, "runtask_id": runTaskID, "data": data}).Where(sq.Eq{"id": id})
	}
)

func (d *DB) InsertObjectQ(tx *sql.Tx, obj stypes.Object, data []byte) error {
	switch obj.GetKind() {
	case types.SequenceKind:
		return d.insertSequenceQ(tx, obj.(*types.Sequence), data)
	case types.ChangeGroupKind:
		return d.insertChangeGroupQ(tx, obj.(*types.ChangeGroup), data)
	case types.RunKind:
		return d.insertRunQ(tx, obj.(*types.Run), data)
	case types.RunConfigKind:
		return d.insertRunConfigQ(tx, obj.(*types.RunConfig), data)
	case types.RunCounterKind:
		return d.insertRunCounterQ(tx, obj.(*types.RunCounter), data)
	case types.RunEventKind:
		return d.insertRunEventQ(tx, obj.(*types.RunEvent), data)
	case types.ExecutorKind:
		return d.insertExecutorQ(tx, obj.(*types.Executor), data)
	case types.ExecutorTaskKind:
		return d.insertExecutorTaskQ(tx, obj.(*types.ExecutorTask), data)
	default:
		panic(errors.Errorf("unknown object kind %q", obj.GetKind()))
	}
}

func (d *DB) insertSequenceQ(tx *sql.Tx, sequence *types.Sequence, data []byte) error {
	q := sequenceQInsert(sequence.ID, sequence.Revision, sequence.SequenceType, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert sequence_q")
	}

	return nil
}

func (d *DB) updateSequenceQ(tx *sql.Tx, sequence *types.Sequence, data []byte) error {
	q := sequenceQUpdate(sequence.ID, sequence.Revision, sequence.SequenceType, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert sequence_q")
	}

	return nil
}

func (d *DB) deleteSequenceQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from sequence_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete sequence_q")
	}

	return nil
}

func (d *DB) insertChangeGroupQ(tx *sql.Tx, changeGroup *types.ChangeGroup, data []byte) error {
	q := changeGroupQInsert(changeGroup.ID, changeGroup.Revision, changeGroup.Name, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert changegroup_q")
	}

	return nil
}

func (d *DB) updateChangeGroupQ(tx *sql.Tx, changeGroup *types.ChangeGroup, data []byte) error {
	q := changeGroupQUpdate(changeGroup.ID, changeGroup.Revision, changeGroup.Name, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert changegroup_q")
	}

	return nil
}

func (d *DB) deleteChangeGroupQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from changegroup_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete changegroup_q")
	}

	return nil
}

func (d *DB) insertRunQ(tx *sql.Tx, run *types.Run, data []byte) error {
	// add ending slash to distinguish between final group (i.e project/projectid/branch/feature and project/projectid/branch/feature02)
	groupPath := run.Group
	if !strings.HasSuffix(groupPath, "/") {
		groupPath += "/"
	}

	q := runQInsert(run.ID, run.Revision, groupPath, run.Sequence, run.Counter, run.Phase, run.Result, run.Archived, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert run_q")
	}

	return nil
}

func (d *DB) updateRunQ(tx *sql.Tx, run *types.Run, data []byte) error {
	// add ending slash to distinguish between final group (i.e project/projectid/branch/feature and project/projectid/branch/feature02)
	groupPath := run.Group
	if !strings.HasSuffix(groupPath, "/") {
		groupPath += "/"
	}

	q := runQUpdate(run.ID, run.Revision, groupPath, run.Sequence, run.Counter, run.Phase, run.Result, run.Archived, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert run_q")
	}

	return nil
}

func (d *DB) deleteRunQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from run_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete run_q")
	}

	return nil
}

func (d *DB) insertRunConfigQ(tx *sql.Tx, runConfig *types.RunConfig, data []byte) error {
	q := runConfigQInsert(runConfig.ID, runConfig.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert runconfig_q")
	}

	return nil
}

func (d *DB) updateRunConfigQ(tx *sql.Tx, runConfig *types.RunConfig, data []byte) error {
	q := runConfigQUpdate(runConfig.ID, runConfig.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert runconfig_q")
	}

	return nil
}

func (d *DB) deleteRunConfigQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from runconfig_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete runconfig_q")
	}

	return nil
}

func (d *DB) insertRunCounterQ(tx *sql.Tx, runCounter *types.RunCounter, data []byte) error {
	q := runCounterQInsert(runCounter.ID, runCounter.Revision, runCounter.GroupID, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert runcounter_q")
	}

	return nil
}

func (d *DB) updateRunCounterQ(tx *sql.Tx, runCounter *types.RunCounter, data []byte) error {
	q := runCounterQUpdate(runCounter.ID, runCounter.Revision, runCounter.GroupID, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert runcounter_q")
	}

	return nil
}

func (d *DB) deleteRunCounterQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from runcounter_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete runcounter_q")
	}

	return nil
}

func (d *DB) insertRunEventQ(tx *sql.Tx, runEvent *types.RunEvent, data []byte) error {
	q := runEventQInsert(runEvent.ID, runEvent.Revision, runEvent.Sequence, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert runevent_q")
	}

	return nil
}

func (d *DB) updateRunEventQ(tx *sql.Tx, runEvent *types.RunEvent, data []byte) error {
	q := runEventQUpdate(runEvent.ID, runEvent.Revision, runEvent.Sequence, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert runevent_q")
	}

	return nil
}

func (d *DB) deleteRunEventQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from runevent_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete runevent_q")
	}

	return nil
}

func (d *DB) insertExecutorQ(tx *sql.Tx, executor *types.Executor, data []byte) error {
	q := executorQInsert(executor.ID, executor.Revision, executor.ExecutorID, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert executor_q")
	}

	return nil
}

func (d *DB) updateExecutorQ(tx *sql.Tx, executor *types.Executor, data []byte) error {
	q := executorQUpdate(executor.ID, executor.Revision, executor.ExecutorID, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert executor_q")
	}

	return nil
}

func (d *DB) deleteExecutorQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from executor_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete executor_q")
	}

	return nil
}

func (d *DB) insertExecutorTaskQ(tx *sql.Tx, executorTask *types.ExecutorTask, data []byte) error {
	q := executorTaskQInsert(executorTask.ID, executorTask.Revision, executorTask.Spec.ExecutorID, executorTask.Spec.RunID, executorTask.Spec.RunTaskID, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert executortask_q")
	}

	return nil
}

func (d *DB) updateExecutorTaskQ(tx *sql.Tx, executorTask *types.ExecutorTask, data []byte) error {
	q := executorTaskQUpdate(executorTask.ID, executorTask.Revision, executorTask.Spec.ExecutorID, executorTask.Spec.RunID, executorTask.Spec.RunTaskID, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert executortask_q")
	}

	return nil
}

func (d *DB) deleteExecutorTaskQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from executortask_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete executortask_q")
	}

	return nil
}
