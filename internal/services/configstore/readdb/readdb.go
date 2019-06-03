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
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sorintlab/agola/internal/datamanager"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/etcd"
	"github.com/sorintlab/agola/internal/objectstorage"
	ostypes "github.com/sorintlab/agola/internal/objectstorage/types"
	"github.com/sorintlab/agola/internal/sequence"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	sq "github.com/Masterminds/squirrel"
	"go.uber.org/zap"
	errors "golang.org/x/xerrors"
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
	ost     *objectstorage.ObjStorage
	dm      *datamanager.DataManager

	Initialized bool
	initMutex   sync.Mutex
}

func NewReadDB(ctx context.Context, logger *zap.Logger, dataDir string, e *etcd.Store, ost *objectstorage.ObjStorage, dm *datamanager.DataManager) (*ReadDB, error) {
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
		ost:     ost,
		dm:      dm,
	}

	return readDB, nil
}

// Initialize populates the readdb with the current etcd data and save the
// revision to then feed it with the etcd events
func (r *ReadDB) Initialize(ctx context.Context) error {
	//  sync the rdb
	if err := r.SyncRDB(ctx); err != nil {
		return errors.Errorf("error syncing db: %w", err)
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

func (r *ReadDB) SyncFromDump() (string, error) {
	dumpIndex, err := r.dm.GetLastDataStatus()
	if err != nil && err != ostypes.ErrNotExist {
		return "", err
	}
	if err == ostypes.ErrNotExist {
		return "", nil
	}
	for dataType, files := range dumpIndex.Files {
		for _, file := range files {
			dumpf, err := r.ost.ReadObject(datamanager.DataFilePath(dataType, file.ID))
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

			err = r.rdb.Do(func(tx *db.Tx) error {
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

	return dumpIndex.WalSequence, nil
}

func (r *ReadDB) SyncFromWals(startWalSeq, endWalSeq string) (string, error) {
	insertfunc := func(walFiles []*datamanager.WalFile) error {
		err := r.rdb.Do(func(tx *db.Tx) error {
			for _, walFile := range walFiles {
				walFilef, err := r.dm.ReadWal(walFile.WalSequence)
				if err != nil {
					return err
				}
				dec := json.NewDecoder(walFilef)
				var header *datamanager.WalHeader
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
		if err := r.ResetDB(); err != nil {
			return err
		}

		var err error
		curWalSeq, err = r.SyncFromDump()
		if err != nil {
			return err
		}
	}

	r.log.Infof("startWalSeq: %s", curWalSeq)

	// Sync from wals
	// sync from objectstorage until the current known lastCommittedStorageWal in
	// etcd since wals are first committed to objectstorage and then in etcd we
	// would like to avoid to store in rdb something that is not yet marked as
	// committedstorage in etcd
	curWalSeq, err = r.SyncFromWals(curWalSeq, lastCommittedStorageWal)
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
		for walElement := range r.dm.ListEtcdWals(ctx, revision) {
			if walElement.Err != nil {
				return err
			}
			if walElement.WalData.WalSequence <= curWalSeq {
				continue
			}

			if err := r.insertCommittedWalSequence(tx, walElement.WalData.WalSequence); err != nil {
				return err
			}

			// update readdb only when the wal has been committed to etcd
			if walElement.WalData.WalStatus != datamanager.WalStatusCommitted {
				return nil
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
			if err := r.insertChangeGroupRevision(tx, changeGroupID, changeGroupRevision); err != nil {
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
		err = r.rdb.Do(func(tx *db.Tx) error {

			// if theres a wal seq epoch change something happened to etcd, usually (if
			// the user hasn't messed up with etcd keys) this means etcd has been reset
			// in such case we should resync from the objectstorage state to ensure we
			// apply all the wal marked as committedstorage (since they could have been
			// lost from etcd)
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
					return errors.Errorf("current rdb wal sequence epoch %d different than new wal sequence epoch %d, resyncing from objectstorage", curWalEpoch, weWalEpoch)
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

func (r *ReadDB) handleEvent(tx *db.Tx, we *datamanager.WatchElement) error {
	//r.log.Debugf("event: %s %q : %q\n", ev.Type, ev.Kv.Key, ev.Kv.Value)
	//key := string(ev.Kv.Key)

	if err := r.handleWalEvent(tx, we); err != nil {
		return err
	}
	return nil
}

func (r *ReadDB) handleWalEvent(tx *db.Tx, we *datamanager.WatchElement) error {
	for cgName, cgRev := range we.ChangeGroupsRevisions {
		if err := r.insertChangeGroupRevision(tx, cgName, cgRev); err != nil {
			return err
		}
	}

	if we.WalData != nil {
		// update readdb only when the wal has been committed to etcd
		if we.WalData.WalStatus != datamanager.WalStatusCommitted {
			return nil
		}

		if err := r.insertCommittedWalSequence(tx, we.WalData.WalSequence); err != nil {
			return err
		}

		r.log.Debugf("applying wal to db")
		return r.applyWal(tx, we.WalData.WalDataFileID)
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
	switch action.ActionType {
	case datamanager.ActionTypePut:
		switch types.ConfigType(action.DataType) {
		case types.ConfigTypeUser:
			if err := r.insertUser(tx, action.Data); err != nil {
				return err
			}
		case types.ConfigTypeOrg:
			if err := r.insertOrg(tx, action.Data); err != nil {
				return err
			}
		case types.ConfigTypeOrgMember:
			if err := r.insertOrgMember(tx, action.Data); err != nil {
				return err
			}
		case types.ConfigTypeProjectGroup:
			if err := r.insertProjectGroup(tx, action.Data); err != nil {
				return err
			}
		case types.ConfigTypeProject:
			if err := r.insertProject(tx, action.Data); err != nil {
				return err
			}
		case types.ConfigTypeRemoteSource:
			if err := r.insertRemoteSource(tx, action.Data); err != nil {
				return err
			}
		case types.ConfigTypeSecret:
			if err := r.insertSecret(tx, action.Data); err != nil {
				return err
			}
		case types.ConfigTypeVariable:
			if err := r.insertVariable(tx, action.Data); err != nil {
				return err
			}
		}

	case datamanager.ActionTypeDelete:
		switch types.ConfigType(action.DataType) {
		case types.ConfigTypeUser:
			r.log.Debugf("deleting user with id: %s", action.ID)
			if err := r.deleteUser(tx, action.ID); err != nil {
				return err
			}
		case types.ConfigTypeOrg:
			r.log.Debugf("deleting org with id: %s", action.ID)
			if err := r.deleteOrg(tx, action.ID); err != nil {
				return err
			}
		case types.ConfigTypeOrgMember:
			r.log.Debugf("deleting orgmember with id: %s", action.ID)
			if err := r.deleteOrgMember(tx, action.ID); err != nil {
				return err
			}
		case types.ConfigTypeProjectGroup:
			r.log.Debugf("deleting project group with id: %s", action.ID)
			if err := r.deleteProjectGroup(tx, action.ID); err != nil {
				return err
			}
		case types.ConfigTypeProject:
			r.log.Debugf("deleting project with id: %s", action.ID)
			if err := r.deleteProject(tx, action.ID); err != nil {
				return err
			}
		case types.ConfigTypeRemoteSource:
			r.log.Debugf("deleting remote source with id: %s", action.ID)
			if err := r.deleteRemoteSource(tx, action.ID); err != nil {
				return err
			}
		case types.ConfigTypeSecret:
			r.log.Debugf("deleting secret with id: %s", action.ID)
			if err := r.deleteSecret(tx, action.ID); err != nil {
				return err
			}
		case types.ConfigTypeVariable:
			r.log.Debugf("deleting variable with id: %s", action.ID)
			if err := r.deleteVariable(tx, action.ID); err != nil {
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
		return 0, errors.Errorf("failed to build query: %w", err)
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
		return errors.Errorf("failed to delete committedwalsequence: %w", err)
	}
	q, args, err := committedwalsequenceInsert.Values(seq).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return err
	}
	return nil
}

func (r *ReadDB) GetCommittedWalSequence(tx *db.Tx) (string, error) {
	var seq string

	q, args, err := committedwalsequenceSelect.OrderBy("seq").Limit(1).ToSql()
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

func (r *ReadDB) insertChangeGroupRevision(tx *db.Tx, changegroup string, revision int64) error {
	r.log.Infof("insertChangeGroupRevision: %s %d", changegroup, revision)

	// poor man insert or update that works because transaction isolation level is serializable
	if _, err := tx.Exec("delete from changegrouprevision where id = $1", changegroup); err != nil {
		return errors.Errorf("failed to delete run: %w", err)
	}
	// insert only if revision > 0
	if revision > 0 {
		q, args, err := changegrouprevisionInsert.Values(changegroup, revision).ToSql()
		if err != nil {
			return errors.Errorf("failed to build query: %w", err)
		}
		if _, err = tx.Exec(q, args...); err != nil {
			return err
		}
	}
	return nil
}

func (r *ReadDB) GetChangeGroupsUpdateTokens(tx *db.Tx, groups []string) (*datamanager.ChangeGroupsUpdateToken, error) {
	s := changegrouprevisionSelect.Where(sq.Eq{"id": groups})
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
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

	return &datamanager.ChangeGroupsUpdateToken{CurRevision: revision, ChangeGroupsRevisions: cgr}, nil
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
			return nil, errors.Errorf("failed to scan rows: %w", err)
		}
		changegroups[id] = revision
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return changegroups, nil
}
