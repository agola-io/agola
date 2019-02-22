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

package wal

import (
	"bytes"
	"container/ring"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"path"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
	"github.com/sorintlab/agola/internal/etcd"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/sequence"

	"github.com/pkg/errors"
	etcdclientv3 "go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/clientv3/concurrency"
	etcdclientv3rpc "go.etcd.io/etcd/etcdserver/api/v3rpc/rpctypes"
	"go.etcd.io/etcd/mvcc/mvccpb"
	"go.uber.org/zap"
)

// TODO(sgotti) handle etcd unwanted changes:
// * Etcd cluster rebuild: we cannot rely on etcd header ClusterID since it could be the same as it's generated using the listen urls. We should add our own clusterid key and use it.
// * Etcd cluster restored to a previous revision: really bad cause should detect that the revision is smaller than the current one

// Storage paths
// wals/{walSeq}
//
// Etcd paths
// wals/{walSeq}

const (
	DefaultEtcdWalsKeepNum = 100
)

var (
	ErrCompacted   = errors.New("required revision has been compacted")
	ErrConcurrency = errors.New("wal concurrency error: change groups already updated")
)

var (
	// Storage paths. Always use path (not filepath) to use the "/" separator
	storageObjectsPrefix = "data/"
	storageWalsDir       = "wals"
	storageWalsStatusDir = path.Join(storageWalsDir, "status")
	storageWalsDataDir   = path.Join(storageWalsDir, "data")

	// etcd paths. Always use path (not filepath) to use the "/" separator
	etcdWalBaseDir                    = "walmanager"
	etcdWalsDir                       = path.Join(etcdWalBaseDir, "wals")
	etcdWalsDataKey                   = path.Join(etcdWalBaseDir, "walsdata")
	etcdWalSeqKey                     = path.Join(etcdWalBaseDir, "walseq")
	etcdLastCommittedStorageWalSeqKey = path.Join(etcdWalBaseDir, "lastcommittedstoragewalseq")

	etcdSyncLockKey       = path.Join(etcdWalBaseDir, "synclock")
	etcdCheckpointLockKey = path.Join(etcdWalBaseDir, "checkpointlock")
	etcdWalCleanerLockKey = path.Join(etcdWalBaseDir, "walcleanerlock")

	etcdChangeGroupsDir           = path.Join(etcdWalBaseDir, "changegroups")
	etcdChangeGroupMinRevisionKey = path.Join(etcdWalBaseDir, "changegroupsminrev")

	etcdPingKey = path.Join(etcdWalBaseDir, "ping")
)

const (
	etcdChangeGroupMinRevisionRange = 1000
)

func (w *WalManager) toStorageDataPath(path string) string {
	return w.basePath + storageObjectsPrefix + path
}

func (w *WalManager) fromStorageDataPath(path string) string {
	return strings.TrimPrefix(path, w.basePath+storageObjectsPrefix)
}

func (w *WalManager) storageWalStatusFile(walSeq string) string {
	return path.Join(w.basePath, storageWalsStatusDir, walSeq)
}

func (w *WalManager) storageWalDataFile(walFileID string) string {
	return path.Join(w.basePath, storageWalsDataDir, walFileID)
}

func etcdWalKey(walSeq string) string {
	return path.Join(etcdWalsDir, walSeq)
}

type ActionType string

const (
	ActionTypePut    ActionType = "put"
	ActionTypeDelete ActionType = "delete"
)

type Action struct {
	ActionType ActionType
	Path       string
	Data       []byte
}

type WalHeader struct {
	WalDataFileID       string
	PreviousWalSequence string
	ChangeGroups        map[string]int64
}

type WalStatus string

const (
	// WalStatusCommitted represent a wal written to the lts
	WalStatusCommitted WalStatus = "committed"
	// WalStatusCommittedStorage represent the .committed marker file written to the lts
	WalStatusCommittedStorage WalStatus = "committed_storage"
	// WalStatusCheckpointed mean that all the wal actions have been executed on the lts
	WalStatusCheckpointed WalStatus = "checkpointed"
)

type WalsData struct {
	LastCommittedWalSequence string
	Revision                 int64 `json:"-"`
}

type WalData struct {
	WalDataFileID       string
	WalStatus           WalStatus
	WalSequence         string
	PreviousWalSequence string
	ChangeGroups        map[string]int64
}

type ChangeGroupsUpdateToken struct {
	CurRevision           int64                 `json:"cur_revision"`
	ChangeGroupsRevisions changeGroupsRevisions `json:"change_groups_revisions"`
}

type changeGroupsRevisions map[string]int64

func (w *WalManager) GetChangeGroupsUpdateToken(cgNames []string) *ChangeGroupsUpdateToken {
	w.changes.Lock()
	revision := w.changes.curRevision()
	cgr := w.changes.getChangeGroups(cgNames)
	w.changes.Unlock()
	return &ChangeGroupsUpdateToken{CurRevision: revision, ChangeGroupsRevisions: cgr}
}

func (w *WalManager) MergeChangeGroupsUpdateTokens(cgts []*ChangeGroupsUpdateToken) *ChangeGroupsUpdateToken {
	mcgt := &ChangeGroupsUpdateToken{ChangeGroupsRevisions: make(changeGroupsRevisions)}
	for _, cgt := range cgts {
		// keep the lower curRevision
		if cgt.CurRevision != 0 && cgt.CurRevision < mcgt.CurRevision {
			mcgt.CurRevision = cgt.CurRevision
		}
		// keep the lower changegroup revision
		for cgName, cgRev := range cgt.ChangeGroupsRevisions {
			if mr, ok := mcgt.ChangeGroupsRevisions[cgName]; ok {
				if cgRev < mr {
					mcgt.ChangeGroupsRevisions[cgName] = cgRev
				}
			} else {
				mcgt.ChangeGroupsRevisions[cgName] = cgRev
			}
		}
	}

	return mcgt
}

func (w *WalManager) ReadObject(p string, cgNames []string) (io.ReadCloser, *ChangeGroupsUpdateToken, error) {
	w.changes.Lock()
	walseq, ok := w.changes.getPut(p)
	revision := w.changes.curRevision()
	cgr := w.changes.getChangeGroups(cgNames)
	actions := w.changes.actions[walseq]
	w.changes.Unlock()

	cgt := &ChangeGroupsUpdateToken{CurRevision: revision, ChangeGroupsRevisions: cgr}

	if ok {
		for _, action := range actions {
			if action.ActionType == ActionTypePut && action.Path == p {
				w.log.Debugf("reading file from wal: %q", action.Path)
				return ioutil.NopCloser(bytes.NewReader(action.Data)), cgt, nil
			}

			additionalActions, err := w.additionalActionsFunc(action)
			if err != nil {
				return nil, nil, err
			}
			for _, action := range additionalActions {
				if action.ActionType == ActionTypePut && action.Path == p {
					w.log.Debugf("reading file from wal additional actions: %q", action.Path)
					return ioutil.NopCloser(bytes.NewReader(action.Data)), cgt, nil
				}
			}
		}
		return nil, nil, errors.Errorf("no file %s in wal %s", p, walseq)
	}

	f, err := w.lts.ReadObject(w.toStorageDataPath(p))
	return f, cgt, err
}

func (w *WalManager) changesList(paths []string, prefix, startWith string, recursive bool) []string {
	fpaths := []string{}
	for _, p := range paths {
		if !recursive && len(p) > len(prefix) {
			rel := strings.TrimPrefix(p, prefix)
			skip := strings.Contains(rel, w.lts.Delimiter())
			if skip {
				continue
			}
		}
		if strings.HasPrefix(p, prefix) && p > startWith {
			fpaths = append(fpaths, p)
		}
	}

	return fpaths
}

func (w *WalManager) List(prefix, startWith string, recursive bool, doneCh <-chan struct{}) <-chan objectstorage.ObjectInfo {
	objectCh := make(chan objectstorage.ObjectInfo, 1)

	prefix = w.toStorageDataPath(prefix)
	startWith = w.toStorageDataPath(startWith)

	w.changes.Lock()
	changesList := w.changesList(w.changes.pathsOrdered, prefix, startWith, recursive)
	deletedChangesMap := w.changes.getDeletesMap()
	w.changes.Unlock()

	ci := 0
	go func(objectCh chan<- objectstorage.ObjectInfo) {
		defer close(objectCh)
		for object := range w.lts.List(prefix, startWith, recursive, doneCh) {
			if object.Err != nil {
				objectCh <- object
				return
			}
			object.Path = w.fromStorageDataPath(object.Path)

			for ci < len(changesList) {
				p := changesList[ci]
				if p < object.Path {
					//w.log.Infof("using path from changelist: %q", p)
					select {
					// Send object content.
					case objectCh <- objectstorage.ObjectInfo{Path: p}:
					// If receives done from the caller, return here.
					case <-doneCh:
						return
					}
					ci++
				} else if p == object.Path {
					ci++
					break
				} else {
					break
				}
			}

			if _, ok := deletedChangesMap[object.Path]; ok {
				continue
			}

			//w.log.Infof("using path from objectstorage: %q", object.Path)
			select {
			// Send object content.
			case objectCh <- object:
			// If receives done from the caller, return here.
			case <-doneCh:
				return
			}
		}
		for ci < len(changesList) {
			//w.log.Infof("using path from changelist: %q", changesList[ci])
			objectCh <- objectstorage.ObjectInfo{
				Path: changesList[ci],
			}
			ci++
		}
	}(objectCh)

	return objectCh
}

func (w *WalManager) HasLtsWal(walseq string) (bool, error) {
	_, err := w.lts.Stat(w.storageWalStatusFile(walseq))
	if err == objectstorage.ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (w *WalManager) ReadWal(walseq string) (io.ReadCloser, error) {
	return w.lts.ReadObject(w.storageWalStatusFile(walseq) + ".committed")
}

func (w *WalManager) ReadWalData(walFileID string) (io.ReadCloser, error) {
	return w.lts.ReadObject(w.storageWalDataFile(walFileID))
}

type WalFile struct {
	WalSequence  string
	Err          error
	Committed    bool
	Checkpointed bool
}

func (w *WalManager) ListLtsWals(start string) <-chan *WalFile {
	walCh := make(chan *WalFile, 1)

	go func() {
		doneCh := make(chan struct{})
		defer close(doneCh)
		defer close(walCh)

		curWal := &WalFile{}
		var startPath string
		if start != "" {
			startPath = w.storageWalStatusFile(start)
		}

		for object := range w.lts.List(path.Join(w.basePath, storageWalsStatusDir)+"/", startPath, true, doneCh) {
			if object.Err != nil {
				walCh <- &WalFile{
					Err: object.Err,
				}
				return
			}

			name := path.Base(object.Path)
			ext := path.Ext(name)
			walSequence := strings.TrimSuffix(name, ext)
			// wal file refers to another wal, so return the current one
			if curWal.WalSequence != walSequence {
				// if this happen something is wrong on the lts
				if !curWal.Committed && curWal.Checkpointed {
					walCh <- &WalFile{
						Err: errors.Errorf("wal is checkpointed but not committed. this should never happen"),
					}
					return
				}

				if curWal.WalSequence != "" {
					// skip not committed wals
					if curWal.Committed {
						walCh <- curWal
					}
				}

				curWal = &WalFile{
					WalSequence: walSequence,
				}
			}

			if ext == ".committed" {
				curWal.Committed = true
			}
			if ext == ".checkpointed" {
				curWal.Checkpointed = true
			}
		}
		if curWal.WalSequence != "" {
			walCh <- curWal
		}
	}()

	return walCh
}

type ListEtcdWalsElement struct {
	WalData *WalData
	Err     error
}

func (w *WalManager) ListEtcdWals(ctx context.Context, revision int64) <-chan *ListEtcdWalsElement {
	walCh := make(chan *ListEtcdWalsElement, 1)

	go func() {
		defer close(walCh)
		var continuation *etcd.ListPagedContinuation
		for {
			listResp, err := w.e.ListPaged(ctx, etcdWalsDir, revision, 10, continuation)
			if err != nil {
				walCh <- &ListEtcdWalsElement{
					Err: err,
				}
				return
			}
			resp := listResp.Resp
			continuation = listResp.Continuation

			for _, kv := range resp.Kvs {
				var walData *WalData
				err := json.Unmarshal(kv.Value, &walData)
				walCh <- &ListEtcdWalsElement{
					WalData: walData,
					Err:     err,
				}
			}
			if !listResp.HasMore {
				break
			}
		}
	}()

	return walCh
}

// FirstAvailableWalData returns the first (the one with smaller sequence) wal
// and returns it (or nil if not available) and the etcd revision at the time of
// the operation
func (w *WalManager) FirstAvailableWalData(ctx context.Context) (*WalData, int64, error) {
	// list waldata and just get the first if available
	listResp, err := w.e.ListPaged(ctx, etcdWalsDir, 0, 1, nil)
	if err != nil {
		return nil, 0, err
	}
	resp := listResp.Resp
	revision := resp.Header.Revision

	if len(resp.Kvs) == 0 {
		return nil, revision, nil
	}

	var walData *WalData
	if err := json.Unmarshal(resp.Kvs[0].Value, &walData); err != nil {
		return nil, 0, err
	}

	return walData, revision, nil
}

func (w *WalManager) LastCommittedStorageWal(ctx context.Context) (string, int64, error) {
	resp, err := w.e.Get(ctx, etcdLastCommittedStorageWalSeqKey)
	if err != nil && err != etcd.ErrKeyNotFound {
		return "", 0, err
	}
	if err == etcd.ErrKeyNotFound {
		return "", 0, errors.Errorf("no last committedstorage wal on etcd")
	}
	lastCommittedStorageWal := string(resp.Kvs[0].Value)
	revision := resp.Header.Revision

	return lastCommittedStorageWal, revision, nil
}

type WatchElement struct {
	Revision              int64
	WalData               *WalData
	ChangeGroupsRevisions changeGroupsRevisions

	Err error
}

func (w *WalManager) Watch(ctx context.Context, revision int64) <-chan *WatchElement {
	walCh := make(chan *WatchElement, 1)

	// TODO(sgotti) if the etcd cluster goes down, watch won't return an error but
	// wait until it comes back. We have to find a way to detect when the cluster
	// is down and report an error so our clients can react (i.e. a readdb could
	// mark itself as not in sync)
	wctx := etcdclientv3.WithRequireLeader(ctx)
	wch := w.e.Watch(wctx, etcdWalBaseDir+"/", revision)

	go func() {
		defer close(walCh)
		for wresp := range wch {
			we := &WatchElement{ChangeGroupsRevisions: make(changeGroupsRevisions)}

			if wresp.Canceled {
				err := wresp.Err()
				switch err {
				case etcdclientv3rpc.ErrCompacted:
					we.Err = ErrCompacted
				default:
					we.Err = err
				}

				walCh <- we
				return
			}

			we.Revision = wresp.Header.Revision

			for _, ev := range wresp.Events {
				key := string(ev.Kv.Key)

				switch {
				case strings.HasPrefix(key, etcdWalsDir+"/"):
					switch ev.Type {
					case mvccpb.PUT:
						var walData *WalData
						if err := json.Unmarshal(ev.Kv.Value, &walData); err != nil {
							we.Err = wresp.Err()
							walCh <- we
							return
						}

						we.WalData = walData
					}

				case strings.HasPrefix(key, etcdChangeGroupsDir+"/"):
					switch ev.Type {
					case mvccpb.PUT:
						changeGroup := path.Base(string(ev.Kv.Key))
						we.ChangeGroupsRevisions[changeGroup] = ev.Kv.ModRevision
					case mvccpb.DELETE:
						changeGroup := path.Base(string(ev.Kv.Key))
						we.ChangeGroupsRevisions[changeGroup] = 0
					}

				default:
					continue
				}
			}

			walCh <- we
		}
	}()

	return walCh
}

// WriteWal writes the provided actions in a wal file. The wal will be marked as
// "committed" on etcd if the provided group changes aren't changed in the
// meantime or a optimistic concurrency error will be returned and the wal won't
// be committed
//
// TODO(sgotti) save inside the wal file also the previous committed wal to
// handle possible lts list operation eventual consistency gaps (list won't
// report a wal at seq X but a wal at X+n, if this kind of eventual consistency
// ever exists)
func (w *WalManager) WriteWal(ctx context.Context, actions []*Action, cgt *ChangeGroupsUpdateToken) (*ChangeGroupsUpdateToken, error) {
	return w.WriteWalAdditionalOps(ctx, actions, cgt, nil, nil)
}

func (w *WalManager) WriteWalAdditionalOps(ctx context.Context, actions []*Action, cgt *ChangeGroupsUpdateToken, cmp []etcdclientv3.Cmp, then []etcdclientv3.Op) (*ChangeGroupsUpdateToken, error) {
	if len(actions) == 0 {
		return nil, errors.Errorf("cannot write wal: actions is empty")
	}

	walSequence, err := sequence.IncSequence(ctx, w.e, etcdWalSeqKey)
	if err != nil {
		return nil, err
	}

	resp, err := w.e.Get(ctx, etcdWalsDataKey)
	if err != nil {
		return nil, err
	}

	var walsData WalsData
	if err := json.Unmarshal(resp.Kvs[0].Value, &walsData); err != nil {
		return nil, err
	}
	walsData.Revision = resp.Kvs[0].ModRevision

	walDataFileID := uuid.NewV4().String()
	walDataFilePath := w.storageWalDataFile(walDataFileID)
	walKey := etcdWalKey(walSequence.String())

	var buf bytes.Buffer
	for _, action := range actions {
		actionj, err := json.Marshal(action)
		if err != nil {
			return nil, err
		}
		if _, err := buf.Write(actionj); err != nil {
			return nil, err
		}
	}
	if err := w.lts.WriteObject(walDataFilePath, bytes.NewReader(buf.Bytes())); err != nil {
		return nil, err
	}
	w.log.Debugf("wrote wal file: %s", walDataFilePath)

	walsData.LastCommittedWalSequence = walSequence.String()

	walData := &WalData{
		WalSequence:   walSequence.String(),
		WalDataFileID: walDataFileID,
		WalStatus:     WalStatusCommitted,
	}

	walsDataj, err := json.Marshal(walsData)
	if err != nil {
		return nil, err
	}
	walDataj, err := json.Marshal(walData)
	if err != nil {
		return nil, err
	}

	if cmp == nil {
		cmp = []etcdclientv3.Cmp{}
	}
	if then == nil {
		then = []etcdclientv3.Op{}
	}

	getWalsData := etcdclientv3.OpGet(etcdWalsDataKey)
	getWal := etcdclientv3.OpGet(walKey)

	//w.log.Infof("cgt: %s", util.Dump(cgt))
	if cgt != nil {
		for cgName, cgRev := range cgt.ChangeGroupsRevisions {
			cgKey := path.Join(etcdChangeGroupsDir, cgName)
			if cgRev > 0 {
				cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.ModRevision(cgKey), "=", cgRev))
			} else {
				cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.CreateRevision(cgKey), "=", 0))
			}
			then = append(then, etcdclientv3.OpPut(cgKey, ""))
		}

		if cgt.CurRevision > 0 {
			cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.ModRevision(etcdChangeGroupMinRevisionKey), "<", cgt.CurRevision+etcdChangeGroupMinRevisionRange))
		}
	}

	cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.ModRevision(etcdWalsDataKey), "=", walsData.Revision))
	cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.Version(walKey), "=", 0))

	then = append(then, etcdclientv3.OpPut(etcdWalsDataKey, string(walsDataj)))
	then = append(then, etcdclientv3.OpPut(walKey, string(walDataj)))

	// This will only succeed if no one else have concurrently updated the walsData
	// TODO(sgotti) retry if it failed due to concurrency errors
	txn := w.e.Client().Txn(ctx).If(cmp...).Then(then...).Else(getWalsData, getWal)
	tresp, err := txn.Commit()
	if err != nil {
		return nil, etcd.FromEtcdError(err)
	}
	if !tresp.Succeeded {
		walsDataRev := tresp.Responses[0].GetResponseRange().Kvs[0].ModRevision
		walDataCreateRev := tresp.Responses[0].GetResponseRange().Kvs[0].CreateRevision

		// TODO(sgotti) If the tx failed due to walsdata already updated we could retry
		if walsDataRev == walsData.Revision && walDataCreateRev == 0 {
			return nil, errors.Errorf("failed to write committed wal: wals groups already updated")
		}
		return nil, ErrConcurrency
	}

	ncgt := &ChangeGroupsUpdateToken{CurRevision: tresp.Header.Revision, ChangeGroupsRevisions: make(changeGroupsRevisions)}
	if cgt != nil {
		for cgName := range cgt.ChangeGroupsRevisions {
			ncgt.ChangeGroupsRevisions[cgName] = tresp.Header.Revision
		}
	}

	// try to commit storage right now
	if err := w.sync(ctx); err != nil {
		w.log.Errorf("wal sync error: %+v", err)
	}

	return ncgt, nil
}

func (w *WalManager) syncLoop(ctx context.Context) {
	for {
		w.log.Debugf("syncer")
		if err := w.sync(ctx); err != nil {
			w.log.Errorf("syncer error: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(5 * time.Second)
	}
}

func (w *WalManager) sync(ctx context.Context) error {
	session, err := concurrency.NewSession(w.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return err
	}
	defer session.Close()

	m := concurrency.NewMutex(session, etcdSyncLockKey)

	if err := m.Lock(ctx); err != nil {
		return err
	}
	defer m.Unlock(ctx)

	resp, err := w.e.List(ctx, etcdWalsDir+"/", "", 0)
	if err != nil {
		return err
	}
	for _, kv := range resp.Kvs {
		var walData WalData
		if err := json.Unmarshal(kv.Value, &walData); err != nil {
			return err
		}
		// wals must be committed and checkpointed in order.
		// TODO(sgotti) this could be optimized by parallelizing writes of wals that don't have common change groups
		switch walData.WalStatus {
		case WalStatusCommitted:
			walFilePath := w.storageWalStatusFile(walData.WalSequence)
			w.log.Debugf("syncing committed wal to storage")
			header := &WalHeader{
				WalDataFileID:       walData.WalDataFileID,
				ChangeGroups:        walData.ChangeGroups,
				PreviousWalSequence: walData.PreviousWalSequence,
			}
			headerj, err := json.Marshal(header)
			if err != nil {
				return err
			}

			walFileCommittedPath := walFilePath + ".committed"
			if err := w.lts.WriteObject(walFileCommittedPath, bytes.NewReader(headerj)); err != nil {
				return err
			}

			w.log.Debugf("updating wal to state %q", WalStatusCommittedStorage)
			walData.WalStatus = WalStatusCommittedStorage
			walDataj, err := json.Marshal(walData)
			if err != nil {
				return err
			}

			cmp := []etcdclientv3.Cmp{}
			then := []etcdclientv3.Op{}
			cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.ModRevision(string(kv.Key)), "=", kv.ModRevision))
			then = append(then, etcdclientv3.OpPut(string(kv.Key), string(walDataj)))
			then = append(then, etcdclientv3.OpPut(string(etcdLastCommittedStorageWalSeqKey), string(walData.WalSequence)))

			// This will only succeed if the no one else have concurrently updated the wal keys in etcd
			txn := w.e.Client().Txn(ctx).If(cmp...).Then(then...)
			tresp, err := txn.Commit()
			if err != nil {
				return etcd.FromEtcdError(err)
			}
			if !tresp.Succeeded {
				return errors.Errorf("failed to write committedstorage wal: concurrent update")
			}
		case WalStatusCheckpointed:
			walFilePath := w.storageWalStatusFile(walData.WalSequence)
			w.log.Debugf("checkpointing committed wal to storage")
			walFileCheckpointedPath := walFilePath + ".checkpointed"
			if err := w.lts.WriteObject(walFileCheckpointedPath, bytes.NewReader([]byte{})); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *WalManager) checkpointLoop(ctx context.Context) {
	for {
		w.log.Debugf("checkpointer")
		if err := w.checkpoint(ctx); err != nil {
			w.log.Errorf("checkpoint error: %v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(2 * time.Second)
	}
}

func (w *WalManager) checkpoint(ctx context.Context) error {
	session, err := concurrency.NewSession(w.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return err
	}
	defer session.Close()

	m := concurrency.NewMutex(session, etcdCheckpointLockKey)

	if err := m.Lock(ctx); err != nil {
		return err
	}
	defer m.Unlock(ctx)

	resp, err := w.e.List(ctx, etcdWalsDir+"/", "", 0)
	if err != nil {
		return err
	}
	for _, kv := range resp.Kvs {
		var walData WalData
		if err := json.Unmarshal(kv.Value, &walData); err != nil {
			return err
		}
		if walData.WalStatus == WalStatusCommitted {
			w.log.Warnf("wal %s not yet committed storage", walData.WalSequence)
			break
		}
		if walData.WalStatus == WalStatusCheckpointed {
			continue
		}
		walFilePath := w.storageWalDataFile(walData.WalDataFileID)
		w.log.Debugf("checkpointing wal: %q", walData.WalSequence)

		walFile, err := w.lts.ReadObject(walFilePath)
		if err != nil {
			return err
		}
		defer walFile.Close()
		dec := json.NewDecoder(walFile)
		for {
			var action *Action

			err := dec.Decode(&action)
			if err == io.EOF {
				// all done
				break
			}
			if err != nil {
				return err
			}

			if err := w.checkpointAction(ctx, action); err != nil {
				return err
			}

			additionalActions, err := w.additionalActionsFunc(action)
			if err != nil {
				return err
			}
			for _, action := range additionalActions {
				if err := w.checkpointAction(ctx, action); err != nil {
					return err
				}
			}
		}

		w.log.Debugf("updating wal to state %q", WalStatusCheckpointed)
		walData.WalStatus = WalStatusCheckpointed
		walDataj, err := json.Marshal(walData)
		if err != nil {
			return err
		}
		if _, err := w.e.AtomicPut(ctx, string(kv.Key), walDataj, kv.ModRevision, nil); err != nil {
			return err
		}
	}
	return nil
}

func (w *WalManager) checkpointAction(ctx context.Context, action *Action) error {
	path := w.toStorageDataPath(action.Path)
	switch action.ActionType {
	case ActionTypePut:
		w.log.Debugf("writing file: %q", path)
		if err := w.lts.WriteObject(path, bytes.NewReader(action.Data)); err != nil {
			return err
		}

	case ActionTypeDelete:
		w.log.Debugf("deleting file: %q", path)
		if err := w.lts.DeleteObject(path); err != nil && err != objectstorage.ErrNotExist {
			return err
		}
	}

	return nil
}

func (w *WalManager) walCleanerLoop(ctx context.Context) {
	for {
		w.log.Debugf("walcleaner")
		if err := w.walCleaner(ctx); err != nil {
			w.log.Errorf("walcleaner error: %v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(2 * time.Second)
	}
}

// walCleaner will clean already checkpointed wals from etcd
// it must always keep at least one wal that is needed for resync operations
// from clients
func (w *WalManager) walCleaner(ctx context.Context) error {
	session, err := concurrency.NewSession(w.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return err
	}
	defer session.Close()

	m := concurrency.NewMutex(session, etcdWalCleanerLockKey)

	if err := m.Lock(ctx); err != nil {
		return err
	}
	defer m.Unlock(ctx)

	resp, err := w.e.List(ctx, etcdWalsDir+"/", "", 0)
	if err != nil {
		return err
	}
	if len(resp.Kvs) <= w.etcdWalsKeepNum {
		return nil
	}
	removeCount := len(resp.Kvs) - w.etcdWalsKeepNum

	for _, kv := range resp.Kvs {
		var walData WalData
		if err := json.Unmarshal(kv.Value, &walData); err != nil {
			return err
		}
		if walData.WalStatus != WalStatusCheckpointed {
			break
		}

		// TODO(sgotti) check that the objectstorage returns the wal actions as checkpointed.
		// With eventual consistent object storages like S3 we shouldn't remove a wal
		// file from etcd (and so from the cache) until we are sure there're no
		// eventual consistency issues. The difficult part is how to check them and be
		// sure that no objects with old data will be returned? Is it enough to read
		// it back or the result could just be luckily correct but another client may
		// arrive to a differnt S3 server that is not yet in sync?
		w.log.Infof("removing wal %q from etcd", walData.WalSequence)
		if _, err := w.e.AtomicDelete(ctx, string(kv.Key), kv.ModRevision); err != nil {
			return err
		}

		removeCount--
		if removeCount == 0 {
			return nil
		}
	}

	return nil
}

func (w *WalManager) compactChangeGroupsLoop(ctx context.Context) {
	for {
		if err := w.compactChangeGroups(ctx); err != nil {
			w.log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(1 * time.Second)
	}
}

func (w *WalManager) compactChangeGroups(ctx context.Context) error {
	resp, err := w.e.Client().Get(ctx, etcdChangeGroupMinRevisionKey)
	if err != nil {
		return err
	}

	revision := resp.Kvs[0].ModRevision

	// first update minrevision
	cmp := etcdclientv3.Compare(etcdclientv3.ModRevision(etcdChangeGroupMinRevisionKey), "=", revision)
	then := etcdclientv3.OpPut(etcdChangeGroupMinRevisionKey, "")
	txn := w.e.Client().Txn(ctx).If(cmp).Then(then)
	tresp, err := txn.Commit()
	if err != nil {
		return etcd.FromEtcdError(err)
	}
	if !tresp.Succeeded {
		return errors.Errorf("failed to update change group min revision key due to concurrent update")
	}

	revision = tresp.Header.Revision

	// then remove all the groups keys with modrevision < minrevision
	resp, err = w.e.List(ctx, etcdChangeGroupsDir, "", 0)
	if err != nil {
		return err
	}
	for _, kv := range resp.Kvs {
		if kv.ModRevision < revision-etcdChangeGroupMinRevisionRange {
			cmp := etcdclientv3.Compare(etcdclientv3.ModRevision(string(kv.Key)), "=", kv.ModRevision)
			then := etcdclientv3.OpDelete(string(kv.Key))
			txn := w.e.Client().Txn(ctx).If(cmp).Then(then)
			tresp, err := txn.Commit()
			if err != nil {
				return etcd.FromEtcdError(err)
			}
			if !tresp.Succeeded {
				w.log.Errorf("failed to update change group min revision key due to concurrent update")
			}
		}
	}
	return nil
}

// etcdPingerLoop periodically updates a key.
// This is used by watchers to inform the client of the current revision
// this is needed since if other users are updating other unwatched keys on
// etcd we won't be notified, not updating the known revisions and thus all the
// walWrites will fails since the provided changegrouptoken will have an old
// revision
// TODO(sgotti) use upcoming etcd 3.4 watch RequestProgress???
func (w *WalManager) etcdPingerLoop(ctx context.Context) {
	for {
		if err := w.etcdPinger(ctx); err != nil {
			w.log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(1 * time.Second)
	}
}

func (w *WalManager) etcdPinger(ctx context.Context) error {
	if _, err := w.e.Put(ctx, etcdPingKey, []byte{}, nil); err != nil {
		return err
	}
	return nil
}

func (w *WalManager) InitEtcd(ctx context.Context) error {
	writeWal := func(wal *WalFile) error {
		w.log.Infof("wal seq: %s", wal.WalSequence)
		walFile, err := w.lts.ReadObject(w.storageWalStatusFile(wal.WalSequence) + ".committed")
		if err != nil {
			return err
		}
		dec := json.NewDecoder(walFile)
		var header *WalHeader
		if err = dec.Decode(&header); err != nil && err != io.EOF {
			walFile.Close()
			return err
		}
		walFile.Close()

		walData := &WalData{
			WalSequence:   wal.WalSequence,
			WalDataFileID: header.WalDataFileID,
			WalStatus:     WalStatusCommitted,
			ChangeGroups:  header.ChangeGroups,
		}
		if wal.Checkpointed {
			walData.WalStatus = WalStatusCheckpointed
		}
		walDataj, err := json.Marshal(walData)
		if err != nil {
			return err
		}

		cmp := []etcdclientv3.Cmp{}
		then := []etcdclientv3.Op{}
		// only add if it doesn't exist
		cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.CreateRevision(etcdWalKey(wal.WalSequence)), "=", 0))
		then = append(then, etcdclientv3.OpPut(etcdWalKey(wal.WalSequence), string(walDataj)))
		txn := w.e.Client().Txn(ctx).If(cmp...).Then(then...)
		tresp, err := txn.Commit()
		if err != nil {
			return etcd.FromEtcdError(err)
		}
		if !tresp.Succeeded {
			return errors.Errorf("failed to sync etcd: wal %q already written", wal.WalSequence)
		}
		return nil
	}

	// Create changegroup min revision if it doesn't exists
	cmp := []etcdclientv3.Cmp{}
	then := []etcdclientv3.Op{}

	cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.CreateRevision(etcdChangeGroupMinRevisionKey), "=", 0))
	then = append(then, etcdclientv3.OpPut(etcdChangeGroupMinRevisionKey, ""))
	txn := w.e.Client().Txn(ctx).If(cmp...).Then(then...)
	if _, err := txn.Commit(); err != nil {
		return etcd.FromEtcdError(err)
	}

	_, err := w.e.Get(ctx, etcdWalsDataKey)
	if err != nil && err != etcd.ErrKeyNotFound {
		return err
	}
	if err == nil {
		return nil
	}

	w.log.Infof("no data found in etcd, initializing")

	// walsdata not found in etcd

	// if there're some wals in the lts this means etcd has been reset.
	// So take all the wals in committed or checkpointed state starting from the
	// first not checkpointed wal and put them in etcd
	lastCommittedStorageWalsRing := ring.New(100)
	lastCommittedStorageWalElem := lastCommittedStorageWalsRing
	lastCommittedStorageWalSequence := ""
	wroteWals := 0
	for wal := range w.ListLtsWals("") {
		w.log.Infof("wal: %s", wal)
		if wal.Err != nil {
			return wal.Err
		}

		lastCommittedStorageWalElem.Value = wal
		lastCommittedStorageWalElem = lastCommittedStorageWalElem.Next()
		lastCommittedStorageWalSequence = wal.WalSequence
		if wal.Checkpointed {
			continue
		}

		if err := writeWal(wal); err != nil {
			return err
		}
		wroteWals++
	}

	// if no wal has been written (because all are checkpointed), write at least
	// the ones in the ring
	if wroteWals == 0 {
		var err error
		lastCommittedStorageWalsRing.Do(func(e interface{}) {
			if e == nil {
				return
			}
			wal := e.(*WalFile)
			err = writeWal(wal)
			if err != nil {
				return
			}
			lastCommittedStorageWalSequence = wal.WalSequence
		})
		if err != nil {
			return err
		}
	}

	walsData := &WalsData{
		LastCommittedWalSequence: lastCommittedStorageWalSequence,
	}
	walsDataj, err := json.Marshal(walsData)
	if err != nil {
		return err
	}

	// save walsdata and lastcommittedstoragewalseq only after writing all the
	// wals in etcd
	// in this way if something fails while adding wals to etcd it'll be retried
	// since waldata doesn't exists
	cmp = []etcdclientv3.Cmp{}
	then = []etcdclientv3.Op{}

	cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.CreateRevision(etcdWalsDataKey), "=", 0))
	then = append(then, etcdclientv3.OpPut(etcdWalsDataKey, string(walsDataj)))
	then = append(then, etcdclientv3.OpPut(etcdLastCommittedStorageWalSeqKey, lastCommittedStorageWalSequence))
	txn = w.e.Client().Txn(ctx).If(cmp...).Then(then...)
	tresp, err := txn.Commit()
	if err != nil {
		return etcd.FromEtcdError(err)
	}
	if !tresp.Succeeded {
		return errors.Errorf("failed to sync etcd: waldata already written")
	}

	return nil
}

type AdditionalActionsFunc func(action *Action) ([]*Action, error)

func NoOpAdditionalActionFunc(action *Action) ([]*Action, error) {
	return []*Action{}, nil
}

type WalManagerConfig struct {
	BasePath              string
	E                     *etcd.Store
	Lts                   *objectstorage.ObjStorage
	AdditionalActionsFunc AdditionalActionsFunc
	EtcdWalsKeepNum       int
}

type WalManager struct {
	basePath              string
	log                   *zap.SugaredLogger
	e                     *etcd.Store
	lts                   *objectstorage.ObjStorage
	changes               *WalChanges
	additionalActionsFunc AdditionalActionsFunc
	etcdWalsKeepNum       int
}

func NewWalManager(ctx context.Context, logger *zap.Logger, conf *WalManagerConfig) (*WalManager, error) {
	if conf.EtcdWalsKeepNum == 0 {
		conf.EtcdWalsKeepNum = DefaultEtcdWalsKeepNum
	}
	if conf.EtcdWalsKeepNum < 1 {
		return nil, errors.New("etcdWalsKeepNum must be greater than 0")
	}

	additionalActionsFunc := conf.AdditionalActionsFunc
	if additionalActionsFunc == nil {
		additionalActionsFunc = NoOpAdditionalActionFunc
	}

	w := &WalManager{
		basePath:              conf.BasePath,
		log:                   logger.Sugar(),
		e:                     conf.E,
		lts:                   conf.Lts,
		additionalActionsFunc: additionalActionsFunc,
		etcdWalsKeepNum:       conf.EtcdWalsKeepNum,
	}

	// add trailing slash the basepath
	if w.basePath != "" && !strings.HasSuffix(w.basePath, "/") {
		w.basePath = w.basePath + "/"
	}

	return w, nil
}

func (w *WalManager) Run(ctx context.Context) error {
	w.changes = NewWalChanges()

	for {
		err := w.InitEtcd(ctx)
		if err == nil {
			break
		}
		w.log.Errorf("failed to initialize etcd: %+v", err)
		time.Sleep(1 * time.Second)
	}

	go w.watcherLoop(ctx)
	go w.syncLoop(ctx)
	go w.checkpointLoop(ctx)
	go w.walCleanerLoop(ctx)
	go w.compactChangeGroupsLoop(ctx)
	go w.etcdPingerLoop(ctx)

	select {
	case <-ctx.Done():
		w.log.Infof("walmanager exiting")
		return nil
	}
}
