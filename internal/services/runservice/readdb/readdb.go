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

	"agola.io/agola/internal/datamanager"
	"agola.io/agola/internal/db"
	"agola.io/agola/internal/etcd"
	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/sequence"
	"agola.io/agola/internal/services/runservice/common"
	"agola.io/agola/internal/services/runservice/store"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/runservice/types"

	sq "github.com/Masterminds/squirrel"
	etcdclientv3 "go.etcd.io/etcd/clientv3"
	etcdclientv3rpc "go.etcd.io/etcd/etcdserver/api/v3rpc/rpctypes"
	"go.etcd.io/etcd/mvcc/mvccpb"
	"go.uber.org/zap"
	errors "golang.org/x/xerrors"
)

const (
	paginationSize = 100
)

var (
	// Use postgresql $ placeholder. It'll be converted to ? from the provided db functions
	sb = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	// readdb tables based on etcd data
	revisionSelect = sb.Select("revision").From("revision")
	revisionInsert = sb.Insert("revision").Columns("revision")

	//runSelect = sb.Select("id", "grouppath", "phase", "result").From("run")
	runInsert = sb.Insert("run").Columns("id", "grouppath", "phase", "result")

	rundataInsert = sb.Insert("rundata").Columns("id", "data")

	//runeventSelect = sb.Select("data").From("runevent")
	runeventInsert = sb.Insert("runevent").Columns("sequence", "data")

	changegrouprevisionSelect = sb.Select("id, revision").From("changegrouprevision")
	changegrouprevisionInsert = sb.Insert("changegrouprevision").Columns("id", "revision")

	// readdb tables based on objectstorage data
	//revisionOSTSelect = sb.Select("revision").From("revision_ost")
	revisionOSTInsert = sb.Insert("revision_ost").Columns("revision")

	//runOSTSelect = sb.Select("id", "grouppath", "phase", "result").From("run_ost")
	runOSTInsert = sb.Insert("run_ost").Columns("id", "grouppath", "phase", "result")

	rundataOSTInsert = sb.Insert("rundata_ost").Columns("id", "data")

	committedwalsequenceOSTSelect = sb.Select("seq").From("committedwalsequence_ost")
	committedwalsequenceOSTInsert = sb.Insert("committedwalsequence_ost").Columns("seq")

	changegrouprevisionOSTSelect = sb.Select("id, revision").From("changegrouprevision_ost")
	changegrouprevisionOSTInsert = sb.Insert("changegrouprevision_ost").Columns("id", "revision")

	runcounterOSTSelect = sb.Select("groupid", "counter").From("runcounter_ost")
	runcounterOSTInsert = sb.Insert("runcounter_ost").Columns("groupid", "counter")
)

type ReadDB struct {
	log     *zap.SugaredLogger
	dataDir string
	e       *etcd.Store
	rdb     *db.DB
	ost     *objectstorage.ObjStorage
	dm      *datamanager.DataManager

	Initialized bool
	initLock    sync.Mutex

	// dbWriteLock is used to have only one concurrent write transaction or sqlite
	// will return a deadlock error (since we are using the unlock/notify api) if
	// two write transactions acquire a lock on each other (we cannot specificy
	// that a transaction will be a write tx so it'll start as a read tx, can
	// acquire a lock on another read tx, when both become write tx the deadlock
	// detector will return an error)
	dbWriteLock sync.Mutex
}

func NewReadDB(ctx context.Context, logger *zap.Logger, dataDir string, e *etcd.Store, ost *objectstorage.ObjStorage, dm *datamanager.DataManager) (*ReadDB, error) {
	if err := os.MkdirAll(dataDir, 0770); err != nil {
		return nil, err
	}

	readDB := &ReadDB{
		log:     logger.Sugar(),
		e:       e,
		dataDir: dataDir,
		ost:     ost,
		dm:      dm,
	}

	return readDB, nil
}

func (r *ReadDB) SetInitialized(initialized bool) {
	r.initLock.Lock()
	r.Initialized = initialized
	r.initLock.Unlock()
}

func (r *ReadDB) IsInitialized() bool {
	r.initLock.Lock()
	defer r.initLock.Unlock()
	return r.Initialized
}

// Initialize populates the readdb with the current etcd data and save the
// revision to then feed it with the etcd events
func (r *ReadDB) Initialize(ctx context.Context) error {
	if err := r.ResetDB(ctx); err != nil {
		return errors.Errorf("failed to reset db: %w", err)
	}
	if err := r.SyncObjectStorage(ctx); err != nil {
		return errors.Errorf("error syncing objectstorage db: %w", err)
	}
	if err := r.SyncRDB(ctx); err != nil {
		return errors.Errorf("error syncing run db: %w", err)
	}
	return nil
}

func (r *ReadDB) ResetDB(ctx context.Context) error {
	// TODO(sgotti) this needs to be protected by a mutex
	if r.rdb != nil {
		r.rdb.Close()
	}

	// drop rdb
	if err := os.Remove(filepath.Join(r.dataDir, "db")); err != nil {
		return err
	}

	rdb, err := db.NewDB(db.Sqlite3, filepath.Join(r.dataDir, "db"))
	if err != nil {
		return err
	}

	// populate readdb
	if err := rdb.Create(ctx, Stmts); err != nil {
		return err
	}

	r.rdb = rdb

	return nil
}

func (r *ReadDB) SyncRDB(ctx context.Context) error {
	err := r.rdb.Do(ctx, func(tx *db.Tx) error {
		// Do pagination to limit the number of keys per request
		var revision int64
		key := common.EtcdRunsDir

		var continuation *etcd.ListPagedContinuation
		for {
			listResp, err := r.e.ListPaged(ctx, key, revision, paginationSize, continuation)
			if err != nil {
				return err
			}
			resp := listResp.Resp
			continuation = listResp.Continuation

			if revision == 0 {
				revision = resp.Header.Revision
			}

			for _, kv := range resp.Kvs {
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

		// sync changegroups, use the same revision of previous operations
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

func (r *ReadDB) Run(ctx context.Context) error {
	if r.rdb != nil {
		r.rdb.Close()
	}
	rdb, err := db.NewDB(db.Sqlite3, filepath.Join(r.dataDir, "db"))
	if err != nil {
		return err
	}

	r.rdb = rdb

	// populate readdb
	if err := r.rdb.Create(ctx, Stmts); err != nil {
		return err
	}

	revision, err := r.GetRevision(ctx)
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

			sleepCh := time.NewTimer(1 * time.Second).C
			select {
			case <-ctx.Done():
				return nil
			case <-sleepCh:
			}
		}
	}
	r.SetInitialized(true)

	for {
		for {
			initialized := r.IsInitialized()
			if initialized {
				break
			}
			err := r.Initialize(ctx)
			if err == nil {
				r.SetInitialized(true)
				break
			}
			r.log.Errorf("initialize err: %+v", err)

			sleepCh := time.NewTimer(1 * time.Second).C
			select {
			case <-ctx.Done():
				return nil
			case <-sleepCh:
			}
		}

		doneCh := make(chan struct{}, 2)
		hctx, cancel := context.WithCancel(ctx)
		wg := &sync.WaitGroup{}

		wg.Add(2)

		go func() {
			r.log.Infof("starting handleEvents")
			if err := r.handleEvents(hctx); err != nil {
				r.log.Errorf("handleEvents err: %+v", err)
			}
			wg.Done()
			doneCh <- struct{}{}
		}()

		go func() {
			r.log.Infof("starting handleEventsOST")
			if err := r.handleEventsOST(hctx); err != nil {
				r.log.Errorf("handleEventsOST err: %+v", err)
			}
			wg.Done()
			doneCh <- struct{}{}
		}()

		select {
		case <-ctx.Done():
			r.log.Infof("readdb exiting")
			cancel()
			return nil
		case <-doneCh:
			// cancel context and wait for the all the goroutines to exit
			cancel()
			wg.Wait()
		}

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			return nil
		case <-sleepCh:
		}
	}
}

func (r *ReadDB) handleEvents(ctx context.Context) error {
	var revision int64
	var lastRuns []*RunData
	err := r.rdb.Do(ctx, func(tx *db.Tx) error {
		var err error
		revision, err = r.getRevision(tx)
		if err != nil {
			return err
		}
		lastRuns, err = r.GetActiveRuns(tx, nil, true, nil, nil, "", 1, types.SortOrderDesc)
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
			r.SetInitialized(false)
			return errors.Errorf("no runsequence in etcd, reinitializing.")
		}

		lastRunSequence, err := sequence.Parse(lastRun.ID)
		if err != nil {
			return err
		}
		// check that the run sequence epoch isn't different than the current one (this means etcd
		// has been reset, or worst, restored from a backup or manually deleted)
		if runSequence.Epoch != lastRunSequence.Epoch {
			r.SetInitialized(false)
			return errors.Errorf("last run epoch %d is different than current epoch in etcd %d, reinitializing.", lastRunSequence.Epoch, runSequence.Epoch)
		}
	}

	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wctx = etcdclientv3.WithRequireLeader(wctx)
	wch := r.e.Watch(wctx, common.EtcdSchedulerBaseDir+"/", revision+1)
	for wresp := range wch {
		if wresp.Canceled {
			err = wresp.Err()
			if err == etcdclientv3rpc.ErrCompacted {
				r.log.Errorf("required events already compacted, reinitializing readdb")
				r.SetInitialized(false)
			}
			return errors.Errorf("watch error: %w", err)
		}

		// a single transaction for every response (every response contains all the
		// events happened in an etcd revision).
		r.dbWriteLock.Lock()
		err = r.rdb.Do(ctx, func(tx *db.Tx) error {
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
		r.dbWriteLock.Unlock()
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
			return errors.Errorf("failed to unmarshal run: %w", err)
		}

		return insertRun(tx, run, ev.Kv.Value)

	case mvccpb.DELETE:
		runID := path.Base(string(ev.Kv.Key))

		if _, err := tx.Exec("delete from run where id = $1", runID); err != nil {
			return errors.Errorf("failed to delete run: %w", err)
		}

		// Run has been deleted from etcd, this means that it was stored in the objectstorage
		// TODO(sgotti) this is here just to avoid a window where the run is not in
		// run table and in the run_os table but should be changed/removed when we'll
		// implement run removal
		run, err := store.OSTGetRun(r.dm, runID)
		if err != nil {
			return err
		}

		return r.insertRunOST(tx, run, []byte{})
	}

	return nil
}

func (r *ReadDB) handleRunsEventEvent(tx *db.Tx, ev *etcdclientv3.Event, wresp *etcdclientv3.WatchResponse) error {
	switch ev.Type {
	case mvccpb.PUT:
		var runEvent *types.RunEvent
		if err := json.Unmarshal(ev.Kv.Value, &runEvent); err != nil {
			return errors.Errorf("failed to unmarshal run: %w", err)
		}
		// poor man insert or update that works because transaction isolation level is serializable
		if _, err := tx.Exec("delete from runevent where sequence = $1", runEvent.Sequence); err != nil {
			return errors.Errorf("failed to delete run: %w", err)
		}
		q, args, err := runeventInsert.Values(runEvent.Sequence, ev.Kv.Value).ToSql()
		if err != nil {
			return errors.Errorf("failed to build query: %w", err)
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
			return errors.Errorf("failed to delete change group revision: %w", err)
		}
	}

	return nil
}

func (r *ReadDB) SyncObjectStorage(ctx context.Context) error {
	// get the last committed storage wal sequence saved in the rdb
	curWalSeq := ""
	err := r.rdb.Do(ctx, func(tx *db.Tx) error {
		var err error
		curWalSeq, err = r.GetCommittedWalSequenceOST(tx)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	lastCommittedStorageWal, _, err := r.dm.LastCommittedStorageWal(ctx)
	if err != nil {
		return err
	}

	doFullSync := false
	if curWalSeq == "" {
		doFullSync = true
		r.log.Warn("no startWalSeq in db, doing a full sync")
	} else {
		ok, err := r.dm.HasOSTWal(curWalSeq)
		if err != nil {
			return err
		}
		if !ok {
			r.log.Warnf("no wal with seq %q in objectstorage, doing a full sync", curWalSeq)
			doFullSync = true
		}

		// if the epoch of the wals has changed this means etcd has been reset. If so
		// we should do a full resync since we are saving in the rdb also data that
		// was not yet committed to objectstorage so we should have the rdb ahead of
		// the current objectstorage data
		// TODO(sgotti) improve this to avoid doing a full resync
		curWalSequence, err := sequence.Parse(curWalSeq)
		if err != nil {
			return err
		}
		curWalEpoch := curWalSequence.Epoch

		lastCommittedStorageWalSequence, err := sequence.Parse(lastCommittedStorageWal)
		if err != nil {
			return err
		}
		if curWalEpoch != lastCommittedStorageWalSequence.Epoch {
			r.log.Warnf("current rdb wal sequence epoch %d different than new wal sequence epoch %d, doing a full sync", curWalEpoch, lastCommittedStorageWalSequence.Epoch)
			doFullSync = true
		}
	}

	if doFullSync {
		r.log.Infof("doing a full sync from dump")
		if err := r.ResetDB(ctx); err != nil {
			return err
		}

		var err error
		curWalSeq, err = r.SyncFromDump(ctx)
		if err != nil {
			return err
		}
	}

	r.log.Debugf("startWalSeq: %s", curWalSeq)

	// Sync from wals
	// sync from objectstorage until the current known lastCommittedStorageWal in etcd
	// since wals are first committed to objectstorage and then in etcd we would like to
	// avoid to store in rdb something that is not yet marked as committedstorage
	// in etcd
	curWalSeq, err = r.SyncFromWals(ctx, curWalSeq, lastCommittedStorageWal)
	if err != nil {
		return errors.Errorf("failed to sync from wals: %w", err)
	}

	// Get the first available wal from etcd and check that our current walseq
	// from wals on objectstorage is >=
	// if not (this happens when syncFromWals takes some time and in the meantime
	// many new wals are written, the next sync should be faster and able to continue
	firstAvailableWalData, revision, err := r.dm.FirstAvailableWalData(ctx)
	if err != nil {
		return errors.Errorf("failed to get first available wal data: %w", err)
	}
	r.log.Debugf("firstAvailableWalData: %s", util.Dump(firstAvailableWalData))
	r.log.Debugf("revision: %d", revision)
	if firstAvailableWalData == nil {
		return errors.Errorf("no wal data in etcd")
	}
	if curWalSeq < firstAvailableWalData.WalSequence {
		return errors.Errorf("current applied wal seq %q is smaller than the first available wal in etcd %q", curWalSeq, firstAvailableWalData.WalSequence)
	}

	r.log.Infof("syncing from wals")
	err = r.rdb.Do(ctx, func(tx *db.Tx) error {
		if err := insertRevisionOST(tx, revision); err != nil {
			return err
		}

		// use the same revision as previous operation
		for walElement := range r.dm.ListEtcdWals(ctx, revision) {
			if walElement.Err != nil {
				return walElement.Err
			}
			if walElement.WalData.WalSequence <= curWalSeq {
				continue
			}

			// update readdb only when the wal has been committed to etcd
			if walElement.WalData.WalStatus != datamanager.WalStatusCommitted {
				return nil
			}

			if err := r.insertCommittedWalSequenceOST(tx, walElement.WalData.WalSequence); err != nil {
				return err
			}

			r.log.Debugf("applying wal to db")
			if err := r.applyWal(tx, walElement.WalData.WalDataFileID); err != nil {
				return err
			}
		}

		// sync changegroups, use the same revision of previous operations
		changeGroupsRevisions, err := r.dm.ListEtcdChangeGroups(ctx, revision)
		if err != nil {
			return err
		}

		for changeGroupID, changeGroupRevision := range changeGroupsRevisions {
			if err := r.insertChangeGroupRevisionOST(tx, changeGroupID, changeGroupRevision); err != nil {
				return err
			}
		}

		return nil
	})

	return err
}

func (r *ReadDB) SyncFromDump(ctx context.Context) (string, error) {
	dumpIndex, err := r.dm.GetLastDataStatus()
	if err != nil {
		return "", err
	}
	for dataType, files := range dumpIndex.Files {
		for _, file := range files {
			dumpf, err := r.ost.ReadObject(r.dm.DataFilePath(dataType, file.ID))
			if err != nil {
				return "", err
			}
			dumpEntries := []*datamanager.DataEntry{}
			dec := json.NewDecoder(dumpf)
			for {
				var de *datamanager.DataEntry

				err := dec.Decode(&de)
				if err == io.EOF {
					// all done
					break
				}
				if err != nil {
					dumpf.Close()
					return "", err
				}
				dumpEntries = append(dumpEntries, de)
			}
			dumpf.Close()

			err = r.rdb.Do(ctx, func(tx *db.Tx) error {
				for _, de := range dumpEntries {
					action := &datamanager.Action{
						ActionType: datamanager.ActionTypePut,
						ID:         de.ID,
						DataType:   dataType,
						Data:       de.Data,
					}
					if err := r.applyAction(tx, action); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return "", err
			}
		}
	}

	err = r.rdb.Do(ctx, func(tx *db.Tx) error {
		if err := r.insertCommittedWalSequenceOST(tx, dumpIndex.WalSequence); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	return dumpIndex.WalSequence, nil
}

func (r *ReadDB) SyncFromWals(ctx context.Context, startWalSeq, endWalSeq string) (string, error) {
	insertfunc := func(walFiles []*datamanager.WalFile) error {
		err := r.rdb.Do(ctx, func(tx *db.Tx) error {
			for _, walFile := range walFiles {
				header, err := r.dm.ReadWal(walFile.WalSequence)
				if err != nil {
					return err
				}
				if err := r.insertCommittedWalSequenceOST(tx, walFile.WalSequence); err != nil {
					return err
				}
				if err := r.applyWal(tx, header.WalDataFileID); err != nil {
					return err
				}
			}
			return nil
		})
		return err
	}

	lastWalSeq := startWalSeq
	walFiles := []*datamanager.WalFile{}
	count := 0

	doneCh := make(chan struct{})
	defer close(doneCh)

	for walFile := range r.dm.ListOSTWals(startWalSeq) {
		if walFile.Err != nil {
			return "", walFile.Err
		}

		walFiles = append(walFiles, walFile)
		lastWalSeq = walFile.WalSequence

		if count > 100 {
			if err := insertfunc(walFiles); err != nil {
				return "", err
			}
			count = 0
			walFiles = []*datamanager.WalFile{}
		} else {
			count++
		}
	}
	if err := insertfunc(walFiles); err != nil {
		return "", err
	}

	return lastWalSeq, nil
}

func (r *ReadDB) handleEventsOST(ctx context.Context) error {
	var revision int64
	err := r.rdb.Do(ctx, func(tx *db.Tx) error {
		err := tx.QueryRow("select revision from revision order by revision desc limit 1").Scan(&revision)
		if err != nil {
			if err == sql.ErrNoRows {
				revision = 0
			} else {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	r.log.Debugf("revision: %d", revision)
	wch := r.dm.Watch(wctx, revision+1)
	for we := range wch {
		r.log.Debugf("we: %s", util.Dump(we))
		if we.Err != nil {
			err := we.Err
			if err == datamanager.ErrCompacted {
				r.log.Warnf("required events already compacted, reinitializing readdb")
				r.Initialized = false
				return nil
			}
			return errors.Errorf("watch error: %w", err)
		}

		// a single transaction for every response (every response contains all the
		// events happened in an etcd revision).
		r.dbWriteLock.Lock()
		err = r.rdb.Do(ctx, func(tx *db.Tx) error {

			// if theres a wal seq epoch change something happened to etcd, usually (if
			// the user hasn't messed up with etcd keys) this means etcd has been reset
			// in such case we should resync from the objectstorage state to ensure we
			// apply all the wal marked as committedstorage (since they could have been
			// lost from etcd)
			curWalSeq, err := r.GetCommittedWalSequenceOST(tx)
			if err != nil {
				return err
			}
			r.log.Debugf("curWalSeq: %q", curWalSeq)
			if curWalSeq != "" && we.WalData != nil {
				curWalSequence, err := sequence.Parse(curWalSeq)
				if err != nil {
					return err
				}
				curWalEpoch := curWalSequence.Epoch

				weWalSequence, err := sequence.Parse(we.WalData.WalSequence)
				if err != nil {
					return err
				}
				r.log.Debugf("we.WalData.WalSequence: %q", we.WalData.WalSequence)
				weWalEpoch := weWalSequence.Epoch
				if curWalEpoch != weWalEpoch {
					r.Initialized = false
					return errors.Errorf("current rdb wal sequence epoch %d different than new wal sequence epoch %d, resyncing from objectstorage", curWalEpoch, weWalEpoch)
				}
			}

			if err := r.handleEventOST(tx, we); err != nil {
				return err
			}

			if err := insertRevisionOST(tx, we.Revision); err != nil {
				return err
			}
			return nil
		})
		r.dbWriteLock.Unlock()
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *ReadDB) applyWal(tx *db.Tx, walDataFileID string) error {
	walFile, err := r.dm.ReadWalData(walDataFileID)
	if err != nil {
		return errors.Errorf("cannot read wal data file %q: %w", walDataFileID, err)
	}
	defer walFile.Close()

	dec := json.NewDecoder(walFile)
	for {
		var action *datamanager.Action

		err := dec.Decode(&action)
		if err == io.EOF {
			// all done
			break
		}
		if err != nil {
			return errors.Errorf("failed to decode wal file: %w", err)
		}

		if err := r.applyAction(tx, action); err != nil {
			return err
		}
	}

	return nil
}

func (r *ReadDB) applyAction(tx *db.Tx, action *datamanager.Action) error {
	r.log.Debugf("action: dataType: %s, ID: %s", action.DataType, action.ID)
	switch action.ActionType {
	case datamanager.ActionTypePut:
		switch action.DataType {
		case string(common.DataTypeRun):
			var run *types.Run
			if err := json.Unmarshal(action.Data, &run); err != nil {
				return err
			}
			if err := r.insertRunOST(tx, run, action.Data); err != nil {
				return err
			}
		case string(common.DataTypeRunCounter):
			var runCounter uint64
			if err := json.Unmarshal(action.Data, &runCounter); err != nil {
				return err
			}
			r.log.Debugf("inserting run counter %q, c: %d", action.ID, runCounter)
			if err := r.insertRunCounterOST(tx, action.ID, runCounter); err != nil {
				return err
			}
		}

	case datamanager.ActionTypeDelete:
		switch action.DataType {
		case string(common.DataTypeRun):
		case string(common.DataTypeRunCounter):
		}
	}

	return nil
}

func (r *ReadDB) handleEventOST(tx *db.Tx, we *datamanager.WatchElement) error {
	//r.log.Debugf("event: %s %q : %q\n", ev.Type, ev.Kv.Key, ev.Kv.Value)
	//key := string(ev.Kv.Key)

	if err := r.handleWalEvent(tx, we); err != nil {
		return err
	}
	return nil
}

func (r *ReadDB) handleWalEvent(tx *db.Tx, we *datamanager.WatchElement) error {
	for cgName, cgRev := range we.ChangeGroupsRevisions {
		if err := r.insertChangeGroupRevisionOST(tx, cgName, cgRev); err != nil {
			return err
		}
	}

	if we.WalData != nil {
		// update readdb only when the wal has been committed to etcd
		if we.WalData.WalStatus != datamanager.WalStatusCommitted {
			return nil
		}

		if err := r.insertCommittedWalSequenceOST(tx, we.WalData.WalSequence); err != nil {
			return err
		}

		r.log.Debugf("applying wal to db")
		return r.applyWal(tx, we.WalData.WalDataFileID)
	}
	return nil
}

func (r *ReadDB) Do(ctx context.Context, f func(tx *db.Tx) error) error {
	if !r.IsInitialized() {
		return errors.Errorf("db not initialized")
	}
	return r.rdb.Do(ctx, f)
}

func insertRevision(tx *db.Tx, revision int64) error {
	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from revision"); err != nil {
		return errors.Errorf("failed to delete revision: %w", err)
	}
	// TODO(sgotti) go database/sql and mattn/sqlite3 don't support uint64 types...
	//q, args, err = revisionInsert.Values(int64(wresp.Header.ClusterId), run.Revision).ToSql()
	q, args, err := revisionInsert.Values(revision).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return err
	}
	return nil
}

func insertRevisionOST(tx *db.Tx, revision int64) error {
	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from revision_ost"); err != nil {
		return errors.Errorf("failed to delete revision: %w", err)
	}
	// TODO(sgotti) go database/sql and mattn/sqlite3 don't support uint64 types...
	//q, args, err = revisionInsert.Values(int64(wresp.Header.ClusterId), run.Revision).ToSql()
	q, args, err := revisionOSTInsert.Values(revision).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return err
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
		return errors.Errorf("failed to delete run: %w", err)
	}
	q, args, err := runInsert.Values(run.ID, groupPath, run.Phase, run.Result).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return err
	}

	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from rundata where id = $1", run.ID); err != nil {
		return errors.Errorf("failed to delete rundata: %w", err)
	}
	q, args, err = rundataInsert.Values(run.ID, data).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return err
	}

	return nil
}

func (r *ReadDB) insertRunOST(tx *db.Tx, run *types.Run, data []byte) error {
	// add ending slash to distinguish between final group (i.e project/projectid/branch/feature and project/projectid/branch/feature02)
	groupPath := run.Group
	if !strings.HasSuffix(groupPath, "/") {
		groupPath += "/"
	}

	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from run_ost where id = $1", run.ID); err != nil {
		return errors.Errorf("failed to delete run objectstorage: %w", err)
	}
	q, args, err := runOSTInsert.Values(run.ID, groupPath, run.Phase, run.Result).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return err
	}

	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from rundata_ost where id = $1", run.ID); err != nil {
		return errors.Errorf("failed to delete rundata: %w", err)
	}
	q, args, err = rundataOSTInsert.Values(run.ID, data).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return err
	}

	return nil
}

func insertChangeGroupRevision(tx *db.Tx, changegroupID string, revision int64) error {
	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from changegrouprevision where id = $1", changegroupID); err != nil {
		return errors.Errorf("failed to delete run: %w", err)
	}
	q, args, err := changegrouprevisionInsert.Values(changegroupID, revision).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return err
	}
	return nil
}

func (r *ReadDB) GetRevision(ctx context.Context) (int64, error) {
	var revision int64

	err := r.rdb.Do(ctx, func(tx *db.Tx) error {
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
		return 0, errors.Errorf("failed to build query: %w", err)
	}

	err = tx.QueryRow(q, args...).Scan(&revision)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return revision, err
}

func (r *ReadDB) GetChangeGroupsUpdateTokens(tx *db.Tx, groups []string) (*types.ChangeGroupsUpdateToken, error) {
	s := changegrouprevisionSelect.Where(sq.Eq{"id": groups})
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
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

func (r *ReadDB) GetActiveRuns(tx *db.Tx, groups []string, lastRun bool, phaseFilter []types.RunPhase, resultFilter []types.RunResult, startRunID string, limit int, sortOrder types.SortOrder) ([]*RunData, error) {
	return r.getRunsFilteredActive(tx, groups, lastRun, phaseFilter, resultFilter, startRunID, limit, sortOrder)
}

func (r *ReadDB) GetRuns(tx *db.Tx, groups []string, lastRun bool, phaseFilter []types.RunPhase, resultFilter []types.RunResult, startRunID string, limit int, sortOrder types.SortOrder) ([]*types.Run, error) {
	useObjectStorage := false
	for _, phase := range phaseFilter {
		if phase == types.RunPhaseFinished || phase == types.RunPhaseCancelled {
			useObjectStorage = true
		}
	}
	if len(phaseFilter) == 0 {
		useObjectStorage = true
	}

	runDataRDB, err := r.getRunsFilteredActive(tx, groups, lastRun, phaseFilter, resultFilter, startRunID, limit, sortOrder)
	if err != nil {
		return nil, err
	}
	lastRunsMap := map[string]*RunData{}
	runsMap := map[string]*RunData{}
	for _, r := range runDataRDB {
		runsMap[r.ID] = r
		lastRunsMap[r.GroupPath] = r
	}

	if useObjectStorage {
		// skip if the phase requested is not finished
		runDataOST, err := r.GetRunsFilteredOST(tx, groups, lastRun, phaseFilter, resultFilter, startRunID, limit, sortOrder)
		if err != nil {
			return nil, err
		}

		for _, rd := range runDataOST {
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

		// get run from objectstorage
		run, err := store.OSTGetRun(r.dm, runID)
		if err != nil {
			return nil, err
		}

		aruns = append(aruns, run)
	}

	return aruns, nil
}

func (r *ReadDB) getRunsFilteredQuery(phaseFilter []types.RunPhase, resultFilter []types.RunResult, groups []string, lastRun bool, startRunID string, limit int, sortOrder types.SortOrder, objectstorage bool) sq.SelectBuilder {
	runt := "run"
	rundatat := "rundata"
	fields := []string{"run.id", "run.grouppath", "run.phase", "rundata.data"}
	if len(groups) > 0 && lastRun {
		fields = []string{"max(run.id)", "run.grouppath", "run.phase", "rundata.data"}
	}
	if objectstorage {
		runt = "run_ost"
		rundatat = "rundata_ost"
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
	if len(resultFilter) > 0 {
		s = s.Where(sq.Eq{"result": resultFilter})
	}
	if startRunID != "" {
		if lastRun {
			switch sortOrder {
			case types.SortOrderAsc:
				s = s.Having(sq.Gt{"run.id": startRunID})
			case types.SortOrderDesc:
				s = s.Having(sq.Lt{"run.id": startRunID})
			}
		} else {
			switch sortOrder {
			case types.SortOrderAsc:
				s = s.Where(sq.Gt{"run.id": startRunID})
			case types.SortOrderDesc:
				s = s.Where(sq.Lt{"run.id": startRunID})
			}
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

func (r *ReadDB) getRunsFilteredActive(tx *db.Tx, groups []string, lastRun bool, phaseFilter []types.RunPhase, resultFilter []types.RunResult, startRunID string, limit int, sortOrder types.SortOrder) ([]*RunData, error) {
	s := r.getRunsFilteredQuery(phaseFilter, resultFilter, groups, lastRun, startRunID, limit, sortOrder, false)

	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	return fetchRuns(tx, q, args...)
}

func (r *ReadDB) GetRunsFilteredOST(tx *db.Tx, groups []string, lastRun bool, phaseFilter []types.RunPhase, resultFilter []types.RunResult, startRunID string, limit int, sortOrder types.SortOrder) ([]*RunData, error) {
	s := r.getRunsFilteredQuery(phaseFilter, resultFilter, groups, lastRun, startRunID, limit, sortOrder, true)

	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	return fetchRuns(tx, q, args...)
}

func (r *ReadDB) GetRun(tx *db.Tx, runID string) (*types.Run, error) {
	run, err := r.getRun(tx, runID, false)
	if err != nil {
		return nil, err
	}
	if run != nil {
		return run, nil
	}

	// try to fetch from ost
	return r.getRun(tx, runID, true)
}

func (r *ReadDB) getRun(tx *db.Tx, runID string, ost bool) (*types.Run, error) {
	s := r.getRunQuery(runID, ost)

	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	runsData, err := fetchRuns(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(runsData) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(runsData) == 0 {
		return nil, nil
	}

	run := runsData[0].Run
	if run == nil {
		var err error
		if !ost {
			return nil, errors.Errorf("nil active run data. This should never happen")
		}
		// get run from objectstorage
		run, err = store.OSTGetRun(r.dm, runID)
		if err != nil {
			return nil, err
		}
	}

	return run, nil
}

func (r *ReadDB) getRunQuery(runID string, objectstorage bool) sq.SelectBuilder {
	runt := "run"
	rundatat := "rundata"
	fields := []string{"run.id", "run.grouppath", "run.phase", "rundata.data"}
	if objectstorage {
		runt = "run_ost"
		rundatat = "rundata_ost"
	}

	s := sb.Select(fields...).From(runt + " as run").Where(sq.Eq{"run.id": runID})
	s = s.Join(fmt.Sprintf("%s as rundata on rundata.id = run.id", rundatat))

	return s
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
		return nil, errors.Errorf("failed to scan rows: %w", err)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &r.Run); err != nil {
			return nil, errors.Errorf("failed to unmarshal run: %w", err)
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
			return nil, errors.Errorf("failed to scan rows: %w", err)
		}
		changegroups[id] = revision
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return changegroups, nil
}

func (r *ReadDB) insertCommittedWalSequenceOST(tx *db.Tx, seq string) error {
	r.log.Debugf("insert seq: %s", seq)
	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from committedwalsequence_ost"); err != nil {
		return errors.Errorf("failed to delete committedwalsequence: %w", err)
	}
	q, args, err := committedwalsequenceOSTInsert.Values(seq).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return err
	}
	return nil
}

func (r *ReadDB) GetCommittedWalSequenceOST(tx *db.Tx) (string, error) {
	var seq string

	q, args, err := committedwalsequenceOSTSelect.OrderBy("seq").Limit(1).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return "", errors.Errorf("failed to build query: %w", err)
	}

	err = tx.QueryRow(q, args...).Scan(&seq)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return seq, err
}

func (r *ReadDB) insertChangeGroupRevisionOST(tx *db.Tx, changegroup string, revision int64) error {
	r.log.Debugf("insertChangeGroupRevision: %s %d", changegroup, revision)

	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from changegrouprevision_ost where id = $1", changegroup); err != nil {
		return errors.Errorf("failed to delete run: %w", err)
	}
	// insert only if revision > 0
	if revision > 0 {
		q, args, err := changegrouprevisionOSTInsert.Values(changegroup, revision).ToSql()
		if err != nil {
			return errors.Errorf("failed to build query: %w", err)
		}
		if _, err = tx.Exec(q, args...); err != nil {
			return err
		}
	}
	return nil
}

func (r *ReadDB) GetChangeGroupsUpdateTokensOST(tx *db.Tx, groups []string) (*datamanager.ChangeGroupsUpdateToken, error) {
	s := changegrouprevisionOSTSelect.Where(sq.Eq{"id": groups})
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}
	cgr, err := fetchChangeGroupsRevisionOST(tx, q, args...)
	if err != nil {
		return nil, err
	}

	revision, err := r.getRevision(tx)
	if err != nil {
		return nil, err
	}

	// for non existing changegroups use a changegroup with revision = 0
	for _, g := range groups {
		if _, ok := cgr[g]; !ok {
			cgr[g] = 0
		}
	}

	return &datamanager.ChangeGroupsUpdateToken{CurRevision: revision, ChangeGroupsRevisions: cgr}, nil
}

func fetchChangeGroupsRevisionOST(tx *db.Tx, q string, args ...interface{}) (map[string]int64, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanChangeGroupsRevisionOST(rows)
}

func scanChangeGroupsRevisionOST(rows *sql.Rows) (map[string]int64, error) {
	changegroups := map[string]int64{}
	for rows.Next() {
		var (
			id       string
			revision int64
		)
		if err := rows.Scan(&id, &revision); err != nil {
			return nil, errors.Errorf("failed to scan rows: %w", err)
		}
		changegroups[id] = revision
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return changegroups, nil
}

func (r *ReadDB) insertRunCounterOST(tx *db.Tx, group string, counter uint64) error {
	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from runcounter_ost where groupid = $1", group); err != nil {
		return errors.Errorf("failed to delete revision: %w", err)
	}
	// TODO(sgotti) go database/sql and mattn/sqlite3 don't support uint64 types...
	//q, args, err = revisionInsert.Values(int64(wresp.Header.ClusterId), run.Revision).ToSql()
	q, args, err := runcounterOSTInsert.Values(group, counter).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return err
	}
	return nil
}

func (r *ReadDB) GetRunCounterOST(tx *db.Tx, group string) (uint64, error) {
	var g string
	var counter uint64

	q, args, err := runcounterOSTSelect.Where(sq.Eq{"groupid": group}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return 0, errors.Errorf("failed to build query: %w", err)
	}

	err = tx.QueryRow(q, args...).Scan(&g, &counter)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return counter, err
}

func (r *ReadDB) GetRunCountersOST(tx *db.Tx, start string, limit int) ([]*types.RunCounter, error) {
	s := runcounterOSTSelect.Where(sq.Gt{"groupid": start})
	if limit > 0 {
		s = s.Limit(uint64(limit))
	}
	s = s.OrderBy("groupid asc")

	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	return fetchRunCounters(tx, q, args...)
}

func fetchRunCounters(tx *db.Tx, q string, args ...interface{}) ([]*types.RunCounter, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRunCounters(rows)
}

func scanRunCounter(rows *sql.Rows) (*types.RunCounter, error) {
	r := &types.RunCounter{}
	if err := rows.Scan(&r.Group, &r.Counter); err != nil {
		return nil, errors.Errorf("failed to scan rows: %w", err)
	}

	return r, nil
}

func scanRunCounters(rows *sql.Rows) ([]*types.RunCounter, error) {
	runCounters := []*types.RunCounter{}
	for rows.Next() {
		r, err := scanRunCounter(rows)
		if err != nil {
			return nil, err
		}
		runCounters = append(runCounters, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return runCounters, nil
}
