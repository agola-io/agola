// Copyright 2019 Sorint.lab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied
// See the License for the specific language governing permissions and
// limitations under the License.

package readdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/etcd"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/sequence"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/common"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/store"
	"github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/util"
	"github.com/sorintlab/agola/internal/wal"
	"go.uber.org/zap"

	sq "github.com/Masterminds/squirrel"
	"github.com/pkg/errors"
	etcdclientv3 "go.etcd.io/etcd/clientv3"
	etcdclientv3rpc "go.etcd.io/etcd/etcdserver/api/v3rpc/rpctypes"
	"go.etcd.io/etcd/mvcc/mvccpb"
)

const (
	paginationSize = 100
)

var (
	// Use postgresql $ placeholder. It'll be converted to ? from the provided db functions
	sb = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	revisionSelect = sb.Select("revision").From("revision")
	revisionInsert = sb.Insert("revision").Columns("revision")

	runSelect = sb.Select("id", "grouppath", "phase").From("run")
	runInsert = sb.Insert("run").Columns("id", "grouppath", "phase")

	rundataInsert = sb.Insert("rundata").Columns("id", "data")

	runeventSelect = sb.Select("data").From("runevent")
	runeventInsert = sb.Insert("runevent").Columns("sequence", "data")

	changegrouprevisionSelect = sb.Select("id, revision").From("changegrouprevision")
	changegrouprevisionInsert = sb.Insert("changegrouprevision").Columns("id", "revision")

	// LTS

	revisionLTSSelect = sb.Select("revision").From("revision_lts")
	revisionLTSInsert = sb.Insert("revision_lts").Columns("revision")

	committedwalsequenceLTSSelect = sb.Select("seq").From("committedwalsequence_lts")
	committedwalsequenceLTSInsert = sb.Insert("committedwalsequence_lts").Columns("seq")

	runLTSSelect = sb.Select("id", "grouppath", "phase").From("run_lts")
	runLTSInsert = sb.Insert("run_lts").Columns("id", "grouppath", "phase")

	rundataLTSInsert = sb.Insert("rundata_lts").Columns("id", "data")
)

type ReadDB struct {
	log     *zap.SugaredLogger
	dataDir string
	e       *etcd.Store
	rdb     *db.DB
	wal     *wal.WalManager

	Initialized bool
	initMutex   sync.Mutex
}

func NewReadDB(ctx context.Context, logger *zap.Logger, dataDir string, e *etcd.Store, wal *wal.WalManager) (*ReadDB, error) {
	if err := os.MkdirAll(dataDir, 0770); err != nil {
		return nil, err
	}
	rdb, err := db.NewDB(db.Sqlite3, filepath.Join(dataDir, "db"))
	if err != nil {
		return nil, err
	}

	// populate readdb
	if err := rdb.Create(Stmts); err != nil {
		return nil, err
	}

	readDB := &ReadDB{
		log:     logger.Sugar(),
		e:       e,
		dataDir: dataDir,
		wal:     wal,
		rdb:     rdb,
	}

	return readDB, nil
}

// Initialize populates the readdb with the current etcd data and save the
// revision to then feed it with the etcd events
func (r *ReadDB) Initialize(ctx context.Context) error {
	if err := r.ResetDB(); err != nil {
		return errors.Wrapf(err, "failed to reset db")
	}
	revision, err := r.SyncLTS(ctx)
	if err != nil {
		return errors.Wrapf(err, "error syncing lts db")
	}
	if err := r.SyncRDB(ctx, revision); err != nil {
		return errors.Wrapf(err, "error syncing run db")
	}
	return nil
}

func (r *ReadDB) ResetDB() error {
	// TODO(sgotti) this needs to be protected by a mutex
	r.rdb.Close()

	// drop rdb
	if err := os.Remove(filepath.Join(r.dataDir, "db")); err != nil {
		return err
	}

	rdb, err := db.NewDB(db.Sqlite3, filepath.Join(r.dataDir, "db"))
	if err != nil {
		return err
	}

	// populate readdb
	if err := rdb.Create(Stmts); err != nil {
		return err
	}

	r.rdb = rdb

	return nil
}

func (r *ReadDB) SyncRDB(ctx context.Context, revision int64) error {
	err := r.rdb.Do(func(tx *db.Tx) error {
		// Do pagination to limit the number of keys per request
		key := common.EtcdRunsDir

		var continuation *etcd.ListPagedContinuation
		for {
			listResp, err := r.e.ListPaged(ctx, key, revision, paginationSize, continuation)
			if err != nil {
				return err
			}
			resp := listResp.Resp
			continuation = listResp.Continuation
			r.log.Infof("continuation: %s", util.Dump(continuation))

			if revision == 0 {
				revision = resp.Header.Revision
			}

			for _, kv := range resp.Kvs {
				r.log.Infof("key: %s", kv.Key)
				var run *types.Run
				if err := json.Unmarshal(kv.Value, &run); err != nil {
					return err
				}

				if err := insertRun(tx, run, kv.Value); err != nil {
					return err
				}
			}

			if !listResp.HasMore {
				break
			}
		}

		// use the same revision
		key = common.EtcdChangeGroupsDir
		continuation = nil
		for {
			listResp, err := r.e.ListPaged(ctx, key, revision, paginationSize, continuation)
			if err != nil {
				return err
			}
			resp := listResp.Resp
			continuation = listResp.Continuation

			for _, kv := range resp.Kvs {
				changegroupID := path.Base(string(kv.Key))

				if err := insertChangeGroupRevision(tx, changegroupID, kv.ModRevision); err != nil {
					return err
				}
			}

			if !listResp.HasMore {
				break
			}
		}

		if err := insertRevision(tx, revision); err != nil {
			return err
		}

		return nil
	})

	return err
}

func (r *ReadDB) SyncLTS(ctx context.Context) (int64, error) {
	type indexData struct {
		ID    string
		Phase types.RunPhase
		Group string
	}

	insertfunc := func(objs []string) error {
		err := r.rdb.Do(func(tx *db.Tx) error {
			for _, obj := range objs {
				f, _, err := r.wal.ReadObject(obj, nil)
				if err != nil {
					if err == objectstorage.ErrNotExist {
						r.log.Warnf("object %s disappeared, ignoring", obj)
					}
					return err
				}

				dec := json.NewDecoder(f)
				for {
					var id *indexData

					err := dec.Decode(&id)
					if err == io.EOF {
						// all done
						break
					}
					if err != nil {
						f.Close()
						return err
					}

					run := &types.Run{
						ID:    id.ID,
						Group: id.Group,
						Phase: id.Phase,
					}
					if err := r.insertRunLTS(tx, run, []byte{}); err != nil {
						f.Close()
						return err
					}
				}
				f.Close()
			}
			return nil
		})
		return err
	}

	resp, err := r.e.Get(ctx, common.EtcdLastIndexKey, 0)
	if err != nil {
		return 0, err
	}
	indexDir := string(resp.Kvs[0].Value)
	indexRevision := resp.Kvs[0].ModRevision
	revision := resp.Header.Revision

	// TODO(sgotti) wait for wal changes to be at a revision >= revision
	walChangesRevision, err := r.wal.ChangesCurrentRevision()
	if err != nil {
		return 0, err
	}
	if walChangesRevision < indexRevision {
		return 0, errors.Errorf("wal changes revision %q is lower than index revision %q", walChangesRevision, revision)
	}

	r.log.Infof("indexDir: %s", indexDir)

	objs := []string{}
	count := 0

	doneCh := make(chan struct{})
	defer close(doneCh)
	for object := range r.wal.List(path.Join(common.StorageRunsIndexesDir, indexDir)+"/", "", true, doneCh) {
		if object.Err != nil {
			return 0, object.Err
		}
		r.log.Infof("path: %s", object.Path)

		objs = append(objs, object.Path)

		if count > paginationSize {
			if err := insertfunc(objs); err != nil {
				return 0, err
			}
			count = 0
			objs = []string{}
		} else {
			count++
		}
	}
	if err := insertfunc(objs); err != nil {
		return 0, err
	}

	resp, err = r.e.Get(ctx, common.EtcdLastIndexKey, 0)
	if err != nil {
		return 0, err
	}
	curIndexDir := string(resp.Kvs[0].Value)

	if curIndexDir != indexDir {
		return 0, errors.Errorf("index dir has changed, used %s, current: %s", indexDir, curIndexDir)
	}

	return revision, nil
}

func (r *ReadDB) Run(ctx context.Context) error {
	revision, err := r.GetRevision()
	if err != nil {
		return err
	}

	if revision == 0 {
		for {
			err := r.Initialize(ctx)
			if err == nil {
				break
			}
			r.log.Errorf("initialize err: %+v", err)

			time.Sleep(1 * time.Second)
		}
	}
	r.Initialized = true

	for {
		for {
			initialized := r.Initialized
			if initialized {
				break
			}
			err := r.Initialize(ctx)
			if err == nil {
				r.Initialized = true
				break
			}
			r.log.Errorf("initialize err: %+v", err)

			time.Sleep(1 * time.Second)
		}

		r.log.Infof("starting HandleEvents")
		if err := r.HandleEvents(ctx); err != nil {
			r.log.Errorf("handleevents err: %+v", err)
		}

		select {
		case <-ctx.Done():
			r.log.Infof("readdb exiting")
			r.rdb.Close()
			return nil
		}

		time.Sleep(1 * time.Second)
	}
}

func (r *ReadDB) HandleEvents(ctx context.Context) error {
	var revision int64
	var lastRuns []*RunData
	err := r.rdb.Do(func(tx *db.Tx) error {
		var err error
		revision, err = r.getRevision(tx)
		if err != nil {
			return err
		}
		lastRuns, err = r.GetActiveRuns(tx, nil, true, nil, "", 1, types.SortOrderDesc)
		return err
	})
	if err != nil {
		return err
	}

	runSequence, _, err := sequence.CurSequence(ctx, r.e, common.EtcdRunSequenceKey)
	if err != nil {
		return err
	}

	var lastRun *types.Run
	if len(lastRuns) > 0 {
		lastRun = lastRuns[0].Run
	}
	if lastRun != nil {
		if runSequence == nil {
			r.Initialized = false
			return errors.Errorf("no runsequence in etcd, reinitializing.")
		}

		lastRunSequence, err := sequence.Parse(lastRun.ID)
		if err != nil {
			return err
		}
		// check that the run sequence epoch isn't different than the current one (this means etcd
		// has been reset, or worst, restored from a backup or manually deleted)
		if runSequence == nil || runSequence.Epoch != lastRunSequence.Epoch {
			r.Initialized = false
			return errors.Errorf("last run epoch %d is different than current epoch in etcd %d, reinitializing.", lastRunSequence.Epoch, runSequence.Epoch)
		}
	}

	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wctx = etcdclientv3.WithRequireLeader(wctx)
	wch := r.e.Watch(wctx, "", revision+1)
	for wresp := range wch {
		if wresp.Canceled {
			err = wresp.Err()
			if err == etcdclientv3rpc.ErrCompacted {
				r.log.Errorf("required events already compacted, reinitializing readdb")
				r.Initialized = false
			}
			return errors.Wrapf(err, "watch error")
		}

		// a single transaction for every response (every response contains all the
		// events happened in an etcd revision).
		err = r.rdb.Do(func(tx *db.Tx) error {
			for _, ev := range wresp.Events {
				if err := r.handleEvent(tx, ev, &wresp); err != nil {
					return err
				}

				if err := insertRevision(tx, ev.Kv.ModRevision); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *ReadDB) handleEvent(tx *db.Tx, ev *etcdclientv3.Event, wresp *etcdclientv3.WatchResponse) error {
	r.log.Debugf("event: %s %q : %q\n", ev.Type, ev.Kv.Key, ev.Kv.Value)
	key := string(ev.Kv.Key)
	switch {
	case strings.HasPrefix(key, common.EtcdRunsDir+"/"):
		return r.handleRunEvent(tx, ev, wresp)

	case strings.HasPrefix(key, common.EtcdChangeGroupsDir+"/"):
		return r.handleChangeGroupEvent(tx, ev, wresp)

	case key == common.EtcdRunEventKey:
		return r.handleRunsEventEvent(tx, ev, wresp)

	default:
		return nil
	}
}

func (r *ReadDB) handleRunEvent(tx *db.Tx, ev *etcdclientv3.Event, wresp *etcdclientv3.WatchResponse) error {
	switch ev.Type {
	case mvccpb.PUT:
		var run *types.Run
		if err := json.Unmarshal(ev.Kv.Value, &run); err != nil {
			return errors.Wrap(err, "failed to unmarshal run")
		}

		return insertRun(tx, run, ev.Kv.Value)

	case mvccpb.DELETE:
		runID := path.Base(string(ev.Kv.Key))

		if _, err := tx.Exec("delete from run where id = $1", runID); err != nil {
			return errors.Wrap(err, "failed to delete run")
		}

		// Run has been deleted from etcd, this means that it was stored in the LTS
		run, err := store.LTSGetRun(r.wal, runID)
		if err != nil {
			return err
		}

		return r.insertRunLTS(tx, run, []byte{})
	}

	return nil
}

func (r *ReadDB) handleRunsEventEvent(tx *db.Tx, ev *etcdclientv3.Event, wresp *etcdclientv3.WatchResponse) error {
	switch ev.Type {
	case mvccpb.PUT:
		var runEvent *common.RunEvent
		if err := json.Unmarshal(ev.Kv.Value, &runEvent); err != nil {
			return errors.Wrap(err, "failed to unmarshal run")
		}
		// poor man insert or update that works because transaction isolation level is serializable
		if _, err := tx.Exec("delete from runevent where sequence = $1", runEvent.Sequence); err != nil {
			return errors.Wrap(err, "failed to delete run")
		}
		q, args, err := runeventInsert.Values(runEvent.Sequence, ev.Kv.Value).ToSql()
		if err != nil {
			return errors.Wrap(err, "failed to build query")
		}
		if _, err = tx.Exec(q, args...); err != nil {
			return err
		}
	}

	return nil
}

func (r *ReadDB) handleChangeGroupEvent(tx *db.Tx, ev *etcdclientv3.Event, wresp *etcdclientv3.WatchResponse) error {
	changegroupID := path.Base(string(ev.Kv.Key))

	switch ev.Type {
	case mvccpb.PUT:
		return insertChangeGroupRevision(tx, changegroupID, ev.Kv.ModRevision)

	case mvccpb.DELETE:
		if _, err := tx.Exec("delete from changegrouprevision where id = $1", changegroupID); err != nil {
			return errors.Wrap(err, "failed to delete change group revision")
		}
	}

	return nil
}

func (r *ReadDB) Do(f func(tx *db.Tx) error) error {
	return r.rdb.Do(f)
}

func insertRevision(tx *db.Tx, revision int64) error {
	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from revision"); err != nil {
		return errors.Wrap(err, "failed to delete revision")
	}
	// TODO(sgotti) go database/sql and mattn/sqlite3 don't support uint64 types...
	//q, args, err = revisionInsert.Values(int64(wresp.Header.ClusterId), run.Revision).ToSql()
	q, args, err := revisionInsert.Values(revision).ToSql()
	if err != nil {
		return errors.Wrap(err, "failed to build query")
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func insertRun(tx *db.Tx, run *types.Run, data []byte) error {
	// add ending slash to distinguish between final group (i.e project/projectid/branch/feature and project/projectid/branch/feature02)
	groupPath := run.Group
	if !strings.HasSuffix(groupPath, "/") {
		groupPath += "/"
	}

	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from run where id = $1", run.ID); err != nil {
		return errors.Wrap(err, "failed to delete run")
	}
	q, args, err := runInsert.Values(run.ID, groupPath, run.Phase).ToSql()
	if err != nil {
		return errors.Wrap(err, "failed to build query")
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return err
	}

	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from rundata where id = $1", run.ID); err != nil {
		return errors.Wrap(err, "failed to delete rundata")
	}
	q, args, err = rundataInsert.Values(run.ID, data).ToSql()
	if err != nil {
		return errors.Wrap(err, "failed to build query")
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return err
	}

	return nil
}

func (r *ReadDB) insertRunLTS(tx *db.Tx, run *types.Run, data []byte) error {
	// add ending slash to distinguish between final group (i.e project/projectid/branch/feature and project/projectid/branch/feature02)
	groupPath := run.Group
	if !strings.HasSuffix(groupPath, "/") {
		groupPath += "/"
	}

	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from run_lts where id = $1", run.ID); err != nil {
		return errors.Wrap(err, "failed to delete run lts")
	}
	q, args, err := runLTSInsert.Values(run.ID, groupPath, run.Phase).ToSql()
	if err != nil {
		return errors.Wrap(err, "failed to build query")
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return err
	}

	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from rundata_lts where id = $1", run.ID); err != nil {
		return errors.Wrap(err, "failed to delete rundata")
	}
	q, args, err = rundataLTSInsert.Values(run.ID, data).ToSql()
	if err != nil {
		return errors.Wrap(err, "failed to build query")
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return err
	}

	return nil
}

func insertChangeGroupRevision(tx *db.Tx, changegroupID string, revision int64) error {
	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from changegrouprevision where id = $1", changegroupID); err != nil {
		return errors.Wrap(err, "failed to delete run")
	}
	q, args, err := changegrouprevisionInsert.Values(changegroupID, revision).ToSql()
	if err != nil {
		return errors.Wrap(err, "failed to build query")
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return err
	}
	return nil
}

func (r *ReadDB) GetRevision() (int64, error) {
	var revision int64

	err := r.rdb.Do(func(tx *db.Tx) error {
		var err error
		revision, err = r.getRevision(tx)
		return err
	})
	return revision, err
}

func (r *ReadDB) getRevision(tx *db.Tx) (int64, error) {
	var revision int64

	q, args, err := revisionSelect.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return 0, errors.Wrap(err, "failed to build query")
	}

	if err := tx.QueryRow(q, args...).Scan(&revision); err == sql.ErrNoRows {
		return 0, nil
	}
	return revision, err
}

func (r *ReadDB) GetChangeGroupsUpdateTokens(tx *db.Tx, groups []string) (*types.ChangeGroupsUpdateToken, error) {
	s := changegrouprevisionSelect.Where(sq.Eq{"id": groups})
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}
	changeGroupsRevisions, err := fetchChangeGroupsRevision(tx, q, args...)
	if err != nil {
		return nil, err
	}

	revision, err := r.getRevision(tx)
	if err != nil {
		return nil, err
	}

	// for non existing changegroups use a changegroup with revision = 0
	for _, g := range groups {
		if _, ok := changeGroupsRevisions[g]; !ok {
			changeGroupsRevisions[g] = 0
		}
	}

	return &types.ChangeGroupsUpdateToken{CurRevision: revision, ChangeGroupsRevisions: changeGroupsRevisions}, nil
}

func (r *ReadDB) GetActiveRuns(tx *db.Tx, groups []string, lastRun bool, phaseFilter []types.RunPhase, startRunID string, limit int, sortOrder types.SortOrder) ([]*RunData, error) {
	return r.getRunsFilteredActive(tx, groups, lastRun, phaseFilter, startRunID, limit, sortOrder)
}

func (r *ReadDB) GetRuns(tx *db.Tx, groups []string, lastRun bool, phaseFilter []types.RunPhase, startRunID string, limit int, sortOrder types.SortOrder) ([]*types.Run, error) {
	useLTS := false
	for _, phase := range phaseFilter {
		if phase == types.RunPhaseFinished || phase == types.RunPhaseCancelled {
			useLTS = true
		}
	}
	if len(phaseFilter) == 0 {
		useLTS = true
	}

	runDataRDB, err := r.getRunsFilteredActive(tx, groups, lastRun, phaseFilter, startRunID, limit, sortOrder)
	if err != nil {
		return nil, err
	}
	lastRunsMap := map[string]*RunData{}
	runsMap := map[string]*RunData{}
	for _, r := range runDataRDB {
		runsMap[r.ID] = r
		lastRunsMap[r.GroupPath] = r
	}

	if useLTS {
		// skip if the phase requested is not finished
		runDataLTS, err := r.GetRunsFilteredLTS(tx, groups, lastRun, phaseFilter, startRunID, limit, sortOrder)
		if err != nil {
			return nil, err
		}

		for _, rd := range runDataLTS {
			if lastRun {
				if lr, ok := lastRunsMap[rd.GroupPath]; ok {
					switch sortOrder {
					case types.SortOrderAsc:
						if rd.ID < lr.ID {
							lastRunsMap[rd.GroupPath] = rd
						}
					case types.SortOrderDesc:
						if rd.ID > lr.ID {
							lastRunsMap[rd.GroupPath] = rd
						}
					}
				} else {
					lastRunsMap[rd.GroupPath] = rd
					runsMap[rd.ID] = rd
				}
			} else {
				runsMap[rd.ID] = rd
			}
		}
	}

	var keys []string
	for k := range runsMap {
		keys = append(keys, k)
	}
	switch sortOrder {
	case types.SortOrderAsc:
		sort.Sort(sort.StringSlice(keys))
	case types.SortOrderDesc:
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	}

	aruns := make([]*types.Run, 0, len(runsMap))

	count := 0
	for _, runID := range keys {
		if count >= limit {
			break
		}
		count++

		rd := runsMap[runID]
		if rd.Run != nil {
			aruns = append(aruns, rd.Run)
			continue
		}

		// get run from lts
		run, err := store.LTSGetRun(r.wal, runID)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		aruns = append(aruns, run)
	}

	return aruns, nil
}

func (r *ReadDB) getRunsFilteredQuery(phaseFilter []types.RunPhase, groups []string, lastRun bool, startRunID string, limit int, sortOrder types.SortOrder, lts bool) sq.SelectBuilder {
	runt := "run"
	rundatat := "rundata"
	fields := []string{"run.id", "run.grouppath", "run.phase", "rundata.data"}
	if len(groups) > 0 && lastRun {
		fields = []string{"max(run.id)", "run.grouppath", "run.phase", "rundata.data"}
	}
	if lts {
		runt = "run_lts"
		rundatat = "rundata_lts"
	}

	r.log.Debugf("runt: %s", runt)
	s := sb.Select(fields...).From(runt + " as run")
	switch sortOrder {
	case types.SortOrderAsc:
		s = s.OrderBy("run.id asc")
	case types.SortOrderDesc:
		s = s.OrderBy("run.id desc")
	}
	if len(phaseFilter) > 0 {
		s = s.Where(sq.Eq{"phase": phaseFilter})
	}
	if startRunID != "" {
		switch sortOrder {
		case types.SortOrderAsc:
			s = s.Where(sq.Gt{"run.id": startRunID})
		case types.SortOrderDesc:
			s = s.Where(sq.Lt{"run.id": startRunID})
		}
	}
	if limit > 0 {
		s = s.Limit(uint64(limit))
	}

	s = s.Join(fmt.Sprintf("%s as rundata on rundata.id = run.id", rundatat))
	if len(groups) > 0 {
		cond := sq.Or{}
		for _, groupPath := range groups {
			// add ending slash to distinguish between final group (i.e project/projectid/branch/feature and project/projectid/branch/feature02)
			if !strings.HasSuffix(groupPath, "/") {
				groupPath += "/"
			}

			cond = append(cond, sq.Like{"run.grouppath": groupPath + "%"})
		}
		s = s.Where(sq.Or{cond})
		if lastRun {
			s = s.GroupBy("run.grouppath")
		}
	}

	return s
}

func (r *ReadDB) getRunsFilteredActive(tx *db.Tx, groups []string, lastRun bool, phaseFilter []types.RunPhase, startRunID string, limit int, sortOrder types.SortOrder) ([]*RunData, error) {
	s := r.getRunsFilteredQuery(phaseFilter, groups, lastRun, startRunID, limit, sortOrder, false)

	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}

	return fetchRuns(tx, q, args...)
}

func (r *ReadDB) GetRunsFilteredLTS(tx *db.Tx, groups []string, lastRun bool, phaseFilter []types.RunPhase, startRunID string, limit int, sortOrder types.SortOrder) ([]*RunData, error) {
	s := r.getRunsFilteredQuery(phaseFilter, groups, lastRun, startRunID, limit, sortOrder, true)

	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}

	return fetchRuns(tx, q, args...)
}

func (r *ReadDB) GetRun(runID string) (*types.Run, error) {
	var run *types.Run

	err := r.rdb.Do(func(tx *db.Tx) error {
		var err error
		run, err = r.getRun(tx, runID)
		return err
	})
	return run, err
}

func (r *ReadDB) getRun(tx *db.Tx, runID string) (*types.Run, error) {
	q, args, err := runSelect.Where(sq.Eq{"id": runID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}

	runs, err := fetchRuns(tx, q, args...)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(runs) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(runs) == 0 {
		return nil, nil
	}
	return runs[0].Run, nil
}

type RunData struct {
	ID        string
	GroupPath string
	Phase     string
	Run       *types.Run
}

func fetchRuns(tx *db.Tx, q string, args ...interface{}) ([]*RunData, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRuns(rows)
}

func scanRun(rows *sql.Rows) (*RunData, error) {
	r := &RunData{}
	var data []byte
	if err := rows.Scan(&r.ID, &r.GroupPath, &r.Phase, &data); err != nil {
		return nil, errors.Wrap(err, "failed to scan rows")
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &r.Run); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal run")
		}
	}

	return r, nil
}

func scanRuns(rows *sql.Rows) ([]*RunData, error) {
	runs := []*RunData{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return runs, nil
}

func fetchChangeGroupsRevision(tx *db.Tx, q string, args ...interface{}) (types.ChangeGroupsRevisions, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanChangeGroupsRevision(rows)
}

func scanChangeGroupsRevision(rows *sql.Rows) (types.ChangeGroupsRevisions, error) {
	changegroups := types.ChangeGroupsRevisions{}
	for rows.Next() {
		var (
			id       string
			revision int64
		)
		if err := rows.Scan(&id, &revision); err != nil {
			return nil, errors.Wrap(err, "failed to scan rows")
		}
		changegroups[id] = revision
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return changegroups, nil
}
