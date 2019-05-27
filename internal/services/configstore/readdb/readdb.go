// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package readdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/etcd"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/sequence"
	"github.com/sorintlab/agola/internal/services/configstore/common"
	"github.com/sorintlab/agola/internal/util"
	"github.com/sorintlab/agola/internal/wal"

	sq "github.com/Masterminds/squirrel"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

var (
	// Use postgresql $ placeholder. It'll be converted to ? from the provided db functions
	sb = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	revisionSelect = sb.Select("revision").From("revision")
	revisionInsert = sb.Insert("revision").Columns("revision")

	committedwalsequenceSelect = sb.Select("seq").From("committedwalsequence")
	committedwalsequenceInsert = sb.Insert("committedwalsequence").Columns("seq")

	changegrouprevisionSelect = sb.Select("id, revision").From("changegrouprevision")
	changegrouprevisionInsert = sb.Insert("changegrouprevision").Columns("id", "revision")
)

type ReadDB struct {
	log     *zap.SugaredLogger
	dataDir string
	e       *etcd.Store
	rdb     *db.DB
	lts     *objectstorage.ObjStorage
	wal     *wal.WalManager

	Initialized bool
	initMutex   sync.Mutex
}

func NewReadDB(ctx context.Context, logger *zap.Logger, dataDir string, e *etcd.Store, lts *objectstorage.ObjStorage, wal *wal.WalManager) (*ReadDB, error) {
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
		dataDir: dataDir,
		rdb:     rdb,
		e:       e,
		lts:     lts,
		wal:     wal,
	}

	return readDB, nil
}

// Initialize populates the readdb with the current etcd data and save the
// revision to then feed it with the etcd events
func (r *ReadDB) Initialize(ctx context.Context) error {
	//  sync the rdb
	if err := r.SyncRDB(ctx); err != nil {
		return errors.Wrapf(err, "error syncing db")
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

func (r *ReadDB) SyncFromFiles() (string, error) {
	doneCh := make(chan struct{})
	defer close(doneCh)

	var lastCheckpointedWal string
	// Get last checkpointed wal from lts
	for wal := range r.wal.ListLtsWals("") {
		if wal.Err != nil {
			return "", wal.Err
		}
		if wal.Checkpointed {
			lastCheckpointedWal = wal.WalSequence
		}
	}

	doneCh = make(chan struct{})
	haveConfigFiles := false
	for object := range r.wal.List(common.StorageDataDir, "", true, doneCh) {
		if object.Err != nil {
			close(doneCh)
			return "", object.Err
		}

		haveConfigFiles = true
		break
	}
	close(doneCh)

	if lastCheckpointedWal == "" && haveConfigFiles {
		return "", errors.Errorf("no last checkpointed wal in lts but the storage has config files. This should never happen!")
	}

	if !haveConfigFiles {
		return lastCheckpointedWal, nil
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
				data, err := ioutil.ReadAll(f)
				if err != nil {
					f.Close()
					return err
				}
				f.Close()

				action := &wal.Action{
					ActionType: wal.ActionTypePut,
					Path:       obj,
					Data:       data,
				}
				if err := r.applyAction(tx, action); err != nil {
					return err
				}
			}
			return nil
		})
		return err
	}

	objs := []string{}
	count := 0
	doneCh = make(chan struct{})
	defer close(doneCh)

	// file may have changed in the meantime (due to checkpointing) but we don't
	// need to have a consistent snapshot since we'll apply all the wals and handle
	// them
	for object := range r.wal.List(common.StorageDataDir, "", true, doneCh) {
		if object.Err != nil {
			return "", object.Err
		}

		objs = append(objs, object.Path)

		if count > 100 {
			if err := insertfunc(objs); err != nil {
				return "", err
			}
			count = 0
			objs = []string{}
		} else {
			count++
		}
	}
	if err := insertfunc(objs); err != nil {
		return "", err
	}

	// save the wal sequence of the last checkpointed wal before syncing from files
	err := r.rdb.Do(func(tx *db.Tx) error {
		return r.insertCommittedWalSequence(tx, lastCheckpointedWal)
	})
	if err != nil {
		return "", err
	}

	return lastCheckpointedWal, nil
}

func (r *ReadDB) SyncFromWals(startWalSeq, endWalSeq string) (string, error) {
	insertfunc := func(walFiles []*wal.WalFile) error {
		err := r.rdb.Do(func(tx *db.Tx) error {
			for _, walFile := range walFiles {
				walFilef, err := r.wal.ReadWal(walFile.WalSequence)
				if err != nil {
					return err
				}
				dec := json.NewDecoder(walFilef)
				var header *wal.WalHeader
				if err = dec.Decode(&header); err != nil && err != io.EOF {
					walFilef.Close()
					return err
				}
				walFilef.Close()
				if err := r.insertCommittedWalSequence(tx, walFile.WalSequence); err != nil {
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
	walFiles := []*wal.WalFile{}
	count := 0

	doneCh := make(chan struct{})
	defer close(doneCh)

	for walFile := range r.wal.ListLtsWals(startWalSeq) {
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
			walFiles = []*wal.WalFile{}
		} else {
			count++
		}
	}
	if err := insertfunc(walFiles); err != nil {
		return "", err
	}

	return lastWalSeq, nil
}

func (r *ReadDB) SyncRDB(ctx context.Context) error {
	// get the last committed storage wal sequence saved in the rdb
	curWalSeq := ""
	err := r.rdb.Do(func(tx *db.Tx) error {
		var err error
		curWalSeq, err = r.GetCommittedWalSequence(tx)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	lastCommittedStorageWal, _, err := r.wal.LastCommittedStorageWal(ctx)
	if err != nil {
		return err
	}

	doFullSync := false
	if curWalSeq == "" {
		doFullSync = true
		r.log.Warn("no startWalSeq in db, doing a full sync")
	} else {
		ok, err := r.wal.HasLtsWal(curWalSeq)
		if err != nil {
			return err
		}
		if !ok {
			r.log.Warnf("no wal with seq %q in lts, doing a full sync", curWalSeq)
			doFullSync = true
		}

		// if the epoch of the wals has changed this means etcd has been reset. If so we should do a full resync since we are saving in the rdb also data that was not yet committed to lts so we should have the rdb ahead of the current lts data
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
		r.log.Infof("doing a full sync from lts files")
		if err := r.ResetDB(); err != nil {
			return err
		}

		var err error
		curWalSeq, err = r.SyncFromFiles()
		if err != nil {
			return err
		}
	}

	r.log.Infof("startWalSeq: %s", curWalSeq)

	// Sync from wals
	// sync from lts until the current known lastCommittedStorageWal in etcd
	// since wals are first committed to lts and then in etcd we would like to
	// avoid to store in rdb something that is not yet marked as committedstorage
	// in etcd
	curWalSeq, err = r.SyncFromWals(curWalSeq, lastCommittedStorageWal)
	if err != nil {
		return errors.Wrap(err, "failed to sync from wals")
	}

	// Get the first available wal from etcd and check that our current walseq
	// from wals on lts is >=
	// if not (this happens when syncFromWals takes some time and in the meantime
	// many new wals are written, the next sync should be faster and able to continue
	firstAvailableWalData, revision, err := r.wal.FirstAvailableWalData(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get first available wal data")
	}
	r.log.Infof("firstAvailableWalData: %s", util.Dump(firstAvailableWalData))
	r.log.Infof("revision: %d", revision)
	if firstAvailableWalData == nil {
		if curWalSeq != "" {
			// this happens if etcd has been reset
			return errors.Errorf("our curwalseq is %q but there's no wal data on etcd", curWalSeq)
		}
	}
	if firstAvailableWalData != nil {
		if curWalSeq < firstAvailableWalData.WalSequence {
			return errors.Errorf("current applied wal seq %q is smaller than the first available wal on etcd %q", curWalSeq, firstAvailableWalData.WalSequence)
		}
	}

	err = r.rdb.Do(func(tx *db.Tx) error {
		if err := r.insertRevision(tx, revision); err != nil {
			return err
		}

		// use the same revision as previous operation
		for walElement := range r.wal.ListEtcdWals(ctx, revision) {
			if walElement.Err != nil {
				return err
			}
			if walElement.WalData.WalSequence <= curWalSeq {
				continue
			}
			//if walElement.WalData.WalStatus == wal.WalStatusCommittedStorage {

			if err := r.insertCommittedWalSequence(tx, walElement.WalData.WalSequence); err != nil {
				return err
			}
			//}

			//// update readdb only when the wal has been committed to lts
			//if walElement.WalData.WalStatus != wal.WalStatusCommittedStorage {
			//	return nil
			//}

			r.log.Debugf("applying wal to db")
			if err := r.applyWal(tx, walElement.WalData.WalDataFileID); err != nil {
				return err
			}
		}

		return nil
	})

	return err
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
				r.Initialized = true
				break
			}
			r.log.Errorf("initialize err: %+v", err)
			time.Sleep(1 * time.Second)
		}
	}

	for {
		if !r.Initialized {
			r.Initialize(ctx)
		}
		if err := r.HandleEvents(ctx); err != nil {
			r.log.Errorf("handleevents err: %+v", err)
		}

		select {
		case <-ctx.Done():
			r.log.Infof("readdb exiting")
			r.rdb.Close()
			return nil
		default:
		}

		time.Sleep(1 * time.Second)
	}
}

// TODO(sgotti) improve to apply when the wal have been "committedstorage" and
// not only "committed", in this way we don't have to full resync when etcd is
// lost/reset
func (r *ReadDB) HandleEvents(ctx context.Context) error {
	var revision int64
	err := r.rdb.Do(func(tx *db.Tx) error {
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
	r.log.Infof("revision: %d", revision)
	wch := r.wal.Watch(wctx, revision+1)
	for we := range wch {
		r.log.Debugf("we: %s", util.Dump(we))
		if we.Err != nil {
			err := we.Err
			if err == wal.ErrCompacted {
				r.log.Warnf("required events already compacted, reinitializing readdb")
				r.Initialized = false
				return nil
			}
			return errors.Wrapf(err, "watch error")
		}

		// a single transaction for every response (every response contains all the
		// events happened in an etcd revision).
		err = r.rdb.Do(func(tx *db.Tx) error {

			// if theres a wal seq epoch change something happened to etcd, usually (if
			// the user hasn't messed up with etcd keys) this means etcd has been reset
			// in such case we should resync from the lts state to ensure we apply all the
			// wal marked as committedstorage (since they could have been lost from etcd)
			curWalSeq, err := r.GetCommittedWalSequence(tx)
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
				r.log.Infof("we.WalData.WalSequence: %q", we.WalData.WalSequence)
				weWalEpoch := weWalSequence.Epoch
				if curWalEpoch != weWalEpoch {
					r.Initialized = false
					return errors.Errorf("current rdb wal sequence epoch %d different than new wal sequence epoch %d, resyncing from lts", curWalEpoch, weWalEpoch)
				}
			}

			if err := r.handleEvent(tx, we); err != nil {
				return err
			}

			if err := r.insertRevision(tx, we.Revision); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	r.log.Infof("wch closed")

	return nil
}

func (r *ReadDB) handleEvent(tx *db.Tx, we *wal.WatchElement) error {
	//r.log.Debugf("event: %s %q : %q\n", ev.Type, ev.Kv.Key, ev.Kv.Value)
	//key := string(ev.Kv.Key)

	if err := r.handleWalEvent(tx, we); err != nil {
		return err
	}
	return nil
}

func (r *ReadDB) handleWalEvent(tx *db.Tx, we *wal.WatchElement) error {
	// update readdb only when the wal has been committed to lts
	//if we.WalData.WalStatus != wal.WalStatusCommittedStorage {
	//	return nil
	//}

	if we.WalData != nil {
		if err := r.insertCommittedWalSequence(tx, we.WalData.WalSequence); err != nil {
			return err
		}
	}

	for cgName, cgRev := range we.ChangeGroupsRevisions {
		if err := r.insertChangeGroupRevision(tx, cgName, cgRev); err != nil {
			return err
		}
	}

	if we.WalData != nil {
		r.log.Debugf("applying wal to db")
		return r.applyWal(tx, we.WalData.WalDataFileID)
	}
	return nil
}

func (r *ReadDB) applyWal(tx *db.Tx, walDataFileID string) error {
	walFile, err := r.wal.ReadWalData(walDataFileID)
	if err != nil {
		return errors.Wrapf(err, "cannot read wal data file %q", walDataFileID)
	}
	defer walFile.Close()

	dec := json.NewDecoder(walFile)
	for {
		var action *wal.Action

		err := dec.Decode(&action)
		if err == io.EOF {
			// all done
			break
		}
		if err != nil {
			return errors.Wrapf(err, "failed to decode wal file")
		}

		if err := r.applyAction(tx, action); err != nil {
			return err
		}
	}

	return nil
}

func (r *ReadDB) applyAction(tx *db.Tx, action *wal.Action) error {
	configType, ID := common.PathToTypeID(action.Path)

	switch action.ActionType {
	case wal.ActionTypePut:
		switch configType {
		case common.ConfigTypeProject:
			if err := r.insertProject(tx, action.Data); err != nil {
				return err
			}
		case common.ConfigTypeUser:
			if err := r.insertUser(tx, action.Data); err != nil {
				return err
			}
		case common.ConfigTypeOrg:
			if err := r.insertOrg(tx, action.Data); err != nil {
				return err
			}
		case common.ConfigTypeRemoteSource:
			if err := r.insertRemoteSource(tx, action.Data); err != nil {
				return err
			}
		}

	case wal.ActionTypeDelete:
		switch configType {
		case common.ConfigTypeProject:
			r.log.Debugf("deleting project with id: %s", ID)
			if err := r.deleteProject(tx, ID); err != nil {
				return err
			}
		case common.ConfigTypeUser:
			r.log.Debugf("deleting user with id: %s", ID)
			if err := r.deleteUser(tx, ID); err != nil {
				return err
			}
		case common.ConfigTypeOrg:
			r.log.Debugf("deleting org with id: %s", ID)
			if err := r.deleteOrg(tx, ID); err != nil {
				return err
			}
		case common.ConfigTypeRemoteSource:
			r.log.Debugf("deleting remote source with id: %s", ID)
			if err := r.deleteRemoteSource(tx, ID); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *ReadDB) Do(f func(tx *db.Tx) error) error {
	return r.rdb.Do(f)
}

func (r *ReadDB) insertRevision(tx *db.Tx, revision int64) error {
	//r.log.Infof("insert revision: %d", revision)
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

	err = tx.QueryRow(q, args...).Scan(&revision)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return revision, err
}

func (r *ReadDB) insertCommittedWalSequence(tx *db.Tx, seq string) error {
	r.log.Infof("insert seq: %s", seq)
	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from committedwalsequence"); err != nil {
		return errors.Wrap(err, "failed to delete committedwalsequence")
	}
	q, args, err := committedwalsequenceInsert.Values(seq).ToSql()
	if err != nil {
		return errors.Wrap(err, "failed to build query")
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (r *ReadDB) GetCommittedWalSequence(tx *db.Tx) (string, error) {
	var seq string

	q, args, err := committedwalsequenceSelect.OrderBy("seq").Limit(1).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return "", errors.Wrap(err, "failed to build query")
	}

	err = tx.QueryRow(q, args...).Scan(&seq)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return seq, err
}

func (r *ReadDB) insertChangeGroupRevision(tx *db.Tx, changegroup string, revision int64) error {
	r.log.Infof("insertChangeGroupRevision: %s %d", changegroup, revision)

	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from changegrouprevision where id = $1", changegroup); err != nil {
		return errors.Wrap(err, "failed to delete run")
	}
	// insert only if revision > 0
	if revision > 0 {
		q, args, err := changegrouprevisionInsert.Values(changegroup, revision).ToSql()
		if err != nil {
			return errors.Wrap(err, "failed to build query")
		}
		if _, err = tx.Exec(q, args...); err != nil {
			return err
		}
	}
	return nil
}

func (r *ReadDB) GetChangeGroupsUpdateTokens(tx *db.Tx, groups []string) (*wal.ChangeGroupsUpdateToken, error) {
	s := changegrouprevisionSelect.Where(sq.Eq{"id": groups})
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build query")
	}
	cgr, err := fetchChangeGroupsRevision(tx, q, args...)
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

	return &wal.ChangeGroupsUpdateToken{CurRevision: revision, ChangeGroupsRevisions: cgr}, nil
}

func fetchChangeGroupsRevision(tx *db.Tx, q string, args ...interface{}) (map[string]int64, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanChangeGroupsRevision(rows)
}

func scanChangeGroupsRevision(rows *sql.Rows) (map[string]int64, error) {
	changegroups := map[string]int64{}
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
