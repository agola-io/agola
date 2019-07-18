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

package datamanager

import (
	"bytes"
	"container/ring"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"path"
	"strings"
	"time"

	"agola.io/agola/internal/etcd"
	ostypes "agola.io/agola/internal/objectstorage/types"
	"agola.io/agola/internal/sequence"

	uuid "github.com/satori/go.uuid"
	etcdclientv3 "go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/clientv3/concurrency"
	etcdclientv3rpc "go.etcd.io/etcd/etcdserver/api/v3rpc/rpctypes"
	"go.etcd.io/etcd/mvcc/mvccpb"
	errors "golang.org/x/xerrors"
)

type ActionType string

const (
	ActionTypePut    ActionType = "put"
	ActionTypeDelete ActionType = "delete"
)

type Action struct {
	ActionType ActionType
	DataType   string
	ID         string
	Data       []byte
}

type WalHeader struct {
	WalDataFileID       string
	PreviousWalSequence string
}

type WalStatus string

const (
	// WalStatusCommitted represent a wal written to the objectstorage
	WalStatusCommitted WalStatus = "committed"
	// WalStatusCommittedStorage represent the .committed marker file written to the objectstorage
	WalStatusCommittedStorage WalStatus = "committed_storage"
	// WalStatusCheckpointed mean that all the wal actions have been executed on the objectstorage
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

	// internal values not saved
	Revision int64 `json:"-"`
}

type ChangeGroupsUpdateToken struct {
	CurRevision           int64                 `json:"cur_revision"`
	ChangeGroupsRevisions changeGroupsRevisions `json:"change_groups_revisions"`
}

type changeGroupsRevisions map[string]int64

func (d *DataManager) GetChangeGroupsUpdateToken(cgNames []string) (*ChangeGroupsUpdateToken, error) {
	d.changes.Lock()
	defer d.changes.Unlock()
	if !d.changes.initialized {
		return nil, errors.Errorf("wal changes not ready")
	}
	revision := d.changes.curRevision()
	cgr := d.changes.getChangeGroups(cgNames)
	return &ChangeGroupsUpdateToken{CurRevision: revision, ChangeGroupsRevisions: cgr}, nil
}

func (d *DataManager) ReadObject(dataType, id string, cgNames []string) (io.ReadCloser, *ChangeGroupsUpdateToken, error) {
	d.changes.Lock()
	if !d.changes.initialized {
		d.changes.Unlock()
		return nil, nil, errors.Errorf("wal changes not ready")
	}
	walseq, ok := d.changes.getPut(dataType, id)
	revision := d.changes.curRevision()
	cgr := d.changes.getChangeGroups(cgNames)
	actions := d.changes.actions[walseq]
	d.changes.Unlock()

	cgt := &ChangeGroupsUpdateToken{CurRevision: revision, ChangeGroupsRevisions: cgr}

	if ok {
		for _, action := range actions {
			if action.ActionType == ActionTypePut {
				if action.DataType == dataType && action.ID == id {
					d.log.Debugf("reading datatype %q, id %q from wal: %q", dataType, id)
					return ioutil.NopCloser(bytes.NewReader(action.Data)), cgt, nil
				}
			}
		}
		return nil, nil, errors.Errorf("no datatype %q, id %q in wal %s", dataType, id, walseq)
	}

	f, err := d.Read(dataType, id)
	return ioutil.NopCloser(f), cgt, err
}

func (d *DataManager) HasOSTWal(walseq string) (bool, error) {
	_, err := d.ost.Stat(d.storageWalStatusFile(walseq) + ".committed")
	if err == ostypes.ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (d *DataManager) ReadWal(walseq string) (io.ReadCloser, error) {
	return d.ost.ReadObject(d.storageWalStatusFile(walseq) + ".committed")
}

func (d *DataManager) ReadWalData(walFileID string) (io.ReadCloser, error) {
	return d.ost.ReadObject(d.storageWalDataFile(walFileID))
}

type WalFile struct {
	WalSequence  string
	Err          error
	Committed    bool
	Checkpointed bool
}

func (d *DataManager) ListOSTWals(start string) <-chan *WalFile {
	walCh := make(chan *WalFile, 1)

	go func() {
		doneCh := make(chan struct{})
		defer close(doneCh)
		defer close(walCh)

		curWal := &WalFile{}
		var startPath string
		if start != "" {
			startPath = d.storageWalStatusFile(start)
		}

		for object := range d.ost.List(path.Join(d.basePath, storageWalsStatusDir)+"/", startPath, true, doneCh) {
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
				// if this happen something is wrong on the objectstorage
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

func (d *DataManager) ListEtcdWals(ctx context.Context, revision int64) <-chan *ListEtcdWalsElement {
	walCh := make(chan *ListEtcdWalsElement, 1)

	go func() {
		defer close(walCh)
		var continuation *etcd.ListPagedContinuation
		for {
			listResp, err := d.e.ListPaged(ctx, etcdWalsDir, revision, 10, continuation)
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

func (d *DataManager) ListEtcdChangeGroups(ctx context.Context, revision int64) (changeGroupsRevisions, error) {
	changeGroupsRevisions := changeGroupsRevisions{}
	resp, err := d.e.List(ctx, etcdChangeGroupsDir, "", revision)
	if err != nil {
		return nil, err
	}
	for _, kv := range resp.Kvs {
		changegroupID := path.Base(string(kv.Key))
		changeGroupsRevisions[changegroupID] = kv.ModRevision
	}

	return changeGroupsRevisions, nil
}

// FirstAvailableWalData returns the first (the one with smaller sequence) wal
// and returns it (or nil if not available) and the etcd revision at the time of
// the operation
func (d *DataManager) FirstAvailableWalData(ctx context.Context) (*WalData, int64, error) {
	// list waldata and just get the first if available
	listResp, err := d.e.ListPaged(ctx, etcdWalsDir, 0, 1, nil)
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

func (d *DataManager) LastCommittedStorageWal(ctx context.Context) (string, int64, error) {
	resp, err := d.e.Get(ctx, etcdLastCommittedStorageWalSeqKey, 0)
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

func (d *DataManager) Watch(ctx context.Context, revision int64) <-chan *WatchElement {
	walCh := make(chan *WatchElement, 1)

	// TODO(sgotti) if the etcd cluster goes down, watch won't return an error but
	// wait until it comes back. We have to find a way to detect when the cluster
	// is down and report an error so our clients can react (i.e. a readdb could
	// mark itself as not in sync)
	wctx := etcdclientv3.WithRequireLeader(ctx)
	wch := d.e.Watch(wctx, etcdWalBaseDir+"/", revision)

	go func() {
		defer close(walCh)
		for wresp := range wch {
			we := &WatchElement{ChangeGroupsRevisions: make(changeGroupsRevisions)}
			send := false

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
					send = true
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
					send = true
					switch ev.Type {
					case mvccpb.PUT:
						changeGroup := path.Base(string(ev.Kv.Key))
						we.ChangeGroupsRevisions[changeGroup] = ev.Kv.ModRevision
					case mvccpb.DELETE:
						changeGroup := path.Base(string(ev.Kv.Key))
						we.ChangeGroupsRevisions[changeGroup] = 0
					}

				case key == etcdPingKey:
					send = true

				default:
					continue
				}
			}

			if send {
				walCh <- we
			}
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
// handle possible objectstorage list operation eventual consistency gaps (list
// won't report a wal at seq X but a wal at X+n, if this kind of eventual
// consistency ever exists)
func (d *DataManager) WriteWal(ctx context.Context, actions []*Action, cgt *ChangeGroupsUpdateToken) (*ChangeGroupsUpdateToken, error) {
	return d.WriteWalAdditionalOps(ctx, actions, cgt, nil, nil)
}

func (d *DataManager) WriteWalAdditionalOps(ctx context.Context, actions []*Action, cgt *ChangeGroupsUpdateToken, cmp []etcdclientv3.Cmp, then []etcdclientv3.Op) (*ChangeGroupsUpdateToken, error) {
	// check changegroups name
	if cgt != nil {
		for cgName := range cgt.ChangeGroupsRevisions {
			if strings.Contains(cgName, "/") {
				return nil, fmt.Errorf(`changegroup name %q must not contain "/"`, cgName)
			}
			if len(cgName) > maxChangegroupNameLength {
				return nil, fmt.Errorf("changegroup name %q too long", cgName)
			}
		}
	}

	if len(actions) == 0 {
		return nil, errors.Errorf("cannot write wal: actions is empty")
	}

	walSequence, err := sequence.IncSequence(ctx, d.e, etcdWalSeqKey)
	if err != nil {
		return nil, err
	}

	resp, err := d.e.Get(ctx, etcdWalsDataKey, 0)
	if err != nil {
		return nil, err
	}

	var walsData WalsData
	if err := json.Unmarshal(resp.Kvs[0].Value, &walsData); err != nil {
		return nil, err
	}
	walsData.Revision = resp.Kvs[0].ModRevision

	walDataFileID := uuid.NewV4().String()
	walDataFilePath := d.storageWalDataFile(walDataFileID)
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
	if err := d.ost.WriteObject(walDataFilePath, bytes.NewReader(buf.Bytes()), int64(buf.Len()), true); err != nil {
		return nil, err
	}
	d.log.Debugf("wrote wal file: %s", walDataFilePath)

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
	txn := d.e.Client().Txn(ctx).If(cmp...).Then(then...).Else(getWalsData, getWal)
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
	if err := d.sync(ctx); err != nil {
		d.log.Errorf("wal sync error: %+v", err)
	}

	return ncgt, nil
}

func (d *DataManager) syncLoop(ctx context.Context) {
	for {
		d.log.Debugf("syncer")
		if err := d.sync(ctx); err != nil {
			d.log.Errorf("syncer error: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(5 * time.Second)
	}
}

func (d *DataManager) sync(ctx context.Context) error {
	session, err := concurrency.NewSession(d.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return err
	}
	defer session.Close()

	m := concurrency.NewMutex(session, etcdSyncLockKey)

	// TODO(sgotti) find a way to use a trylock so we'll just return if already
	// locked. Currently multiple task updaters will enqueue and start when another
	// finishes (unuseful and consume resources)
	if err := m.Lock(ctx); err != nil {
		return err
	}
	defer func() { _ = m.Unlock(ctx) }()

	resp, err := d.e.List(ctx, etcdWalsDir+"/", "", 0)
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
			walFilePath := d.storageWalStatusFile(walData.WalSequence)
			d.log.Debugf("syncing committed wal %q to storage", walData.WalSequence)
			header := &WalHeader{
				WalDataFileID:       walData.WalDataFileID,
				PreviousWalSequence: walData.PreviousWalSequence,
			}
			headerj, err := json.Marshal(header)
			if err != nil {
				return err
			}

			walFileCommittedPath := walFilePath + ".committed"
			if err := d.ost.WriteObject(walFileCommittedPath, bytes.NewReader(headerj), int64(len(headerj)), true); err != nil {
				return err
			}

			d.log.Debugf("updating wal to state %q", WalStatusCommittedStorage)
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
			txn := d.e.Client().Txn(ctx).If(cmp...).Then(then...)
			tresp, err := txn.Commit()
			if err != nil {
				return etcd.FromEtcdError(err)
			}
			if !tresp.Succeeded {
				return errors.Errorf("failed to write committedstorage wal: concurrent update")
			}
		case WalStatusCheckpointed:
			walFilePath := d.storageWalStatusFile(walData.WalSequence)
			d.log.Debugf("checkpointing committed wal to storage")
			walFileCheckpointedPath := walFilePath + ".checkpointed"
			if err := d.ost.WriteObject(walFileCheckpointedPath, bytes.NewReader([]byte{}), 0, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *DataManager) checkpointLoop(ctx context.Context) {
	for {
		d.log.Debugf("checkpointer")
		if err := d.checkpoint(ctx, false); err != nil {
			d.log.Errorf("checkpoint error: %v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(d.checkpointInterval)
	}
}

func (d *DataManager) checkpoint(ctx context.Context, force bool) error {
	session, err := concurrency.NewSession(d.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return err
	}
	defer session.Close()

	m := concurrency.NewMutex(session, etcdCheckpointLockKey)

	// TODO(sgotti) find a way to use a trylock so we'll just return if already
	// locked. Currently multiple task updaters will enqueue and start when another
	// finishes (unuseful and consume resources)
	if err := m.Lock(ctx); err != nil {
		return err
	}
	defer func() { _ = m.Unlock(ctx) }()

	resp, err := d.e.List(ctx, etcdWalsDir+"/", "", 0)
	if err != nil {
		return err
	}
	walsData := []*WalData{}
	for _, kv := range resp.Kvs {
		var walData *WalData
		if err := json.Unmarshal(kv.Value, &walData); err != nil {
			return err
		}
		walData.Revision = kv.ModRevision

		if walData.WalStatus == WalStatusCommitted {
			d.log.Warnf("wal %s not yet committed storage", walData.WalSequence)
			break
		}
		if walData.WalStatus == WalStatusCheckpointed {
			continue
		}
		walsData = append(walsData, walData)
	}

	if !force && len(walsData) < d.minCheckpointWalsNum {
		return nil
	}
	if len(walsData) == 0 {
		return nil
	}

	if err := d.writeDataSnapshot(ctx, walsData); err != nil {
		return errors.Errorf("checkpoint function error: %w", err)
	}

	for _, walData := range walsData {
		d.log.Debugf("updating wal to state %q", WalStatusCheckpointed)
		walData.WalStatus = WalStatusCheckpointed
		walDataj, err := json.Marshal(walData)
		if err != nil {
			return err
		}
		walKey := etcdWalKey(walData.WalSequence)
		if _, err := d.e.AtomicPut(ctx, walKey, walDataj, walData.Revision, nil); err != nil {
			return err
		}
	}

	return nil
}

func (d *DataManager) walCleanerLoop(ctx context.Context) {
	for {
		d.log.Debugf("walcleaner")
		if err := d.walCleaner(ctx); err != nil {
			d.log.Errorf("walcleaner error: %v", err)
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
func (d *DataManager) walCleaner(ctx context.Context) error {
	session, err := concurrency.NewSession(d.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return err
	}
	defer session.Close()

	m := concurrency.NewMutex(session, etcdWalCleanerLockKey)

	// TODO(sgotti) find a way to use a trylock so we'll just return if already
	// locked. Currently multiple task updaters will enqueue and start when another
	// finishes (unuseful and consume resources)
	if err := m.Lock(ctx); err != nil {
		return err
	}
	defer func() { _ = m.Unlock(ctx) }()

	resp, err := d.e.List(ctx, etcdWalsDir+"/", "", 0)
	if err != nil {
		return err
	}
	if len(resp.Kvs) <= d.etcdWalsKeepNum {
		return nil
	}
	removeCount := len(resp.Kvs) - d.etcdWalsKeepNum

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
		d.log.Infof("removing wal %q from etcd", walData.WalSequence)
		if _, err := d.e.AtomicDelete(ctx, string(kv.Key), kv.ModRevision); err != nil {
			return err
		}

		removeCount--
		if removeCount == 0 {
			return nil
		}
	}

	return nil
}

func (d *DataManager) compactChangeGroupsLoop(ctx context.Context) {
	for {
		if err := d.compactChangeGroups(ctx); err != nil {
			d.log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(1 * time.Second)
	}
}

func (d *DataManager) compactChangeGroups(ctx context.Context) error {
	session, err := concurrency.NewSession(d.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return err
	}
	defer session.Close()

	m := concurrency.NewMutex(session, etcdCompactChangeGroupsLockKey)

	// TODO(sgotti) find a way to use a trylock so we'll just return if already
	// locked. Currently multiple task updaters will enqueue and start when another
	// finishes (unuseful and consume resources)
	if err := m.Lock(ctx); err != nil {
		return err
	}
	defer func() { _ = m.Unlock(ctx) }()

	resp, err := d.e.Client().Get(ctx, etcdChangeGroupMinRevisionKey)
	if err != nil {
		return err
	}

	if len(resp.Kvs) == 0 {
		return errors.Errorf("no change group min revision key in etcd")
	}
	revision := resp.Kvs[0].ModRevision

	// first update minrevision
	cmp := etcdclientv3.Compare(etcdclientv3.ModRevision(etcdChangeGroupMinRevisionKey), "=", revision)
	then := etcdclientv3.OpPut(etcdChangeGroupMinRevisionKey, "")
	txn := d.e.Client().Txn(ctx).If(cmp).Then(then)
	tresp, err := txn.Commit()
	if err != nil {
		return etcd.FromEtcdError(err)
	}
	if !tresp.Succeeded {
		return errors.Errorf("failed to update change group min revision key due to concurrent update")
	}

	revision = tresp.Header.Revision

	// then remove all the groups keys with modrevision < minrevision
	resp, err = d.e.List(ctx, etcdChangeGroupsDir, "", 0)
	if err != nil {
		return err
	}
	for _, kv := range resp.Kvs {
		if kv.ModRevision < revision-etcdChangeGroupMinRevisionRange {
			cmp := etcdclientv3.Compare(etcdclientv3.ModRevision(string(kv.Key)), "=", kv.ModRevision)
			then := etcdclientv3.OpDelete(string(kv.Key))
			txn := d.e.Client().Txn(ctx).If(cmp).Then(then)
			tresp, err := txn.Commit()
			if err != nil {
				return etcd.FromEtcdError(err)
			}
			if !tresp.Succeeded {
				d.log.Errorf("failed to update change group min revision key due to concurrent update")
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
func (d *DataManager) etcdPingerLoop(ctx context.Context) {
	for {
		if err := d.etcdPinger(ctx); err != nil {
			d.log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(1 * time.Second)
	}
}

func (d *DataManager) etcdPinger(ctx context.Context) error {
	if _, err := d.e.Put(ctx, etcdPingKey, []byte{}, nil); err != nil {
		return err
	}
	return nil
}

func (d *DataManager) InitEtcd(ctx context.Context, dataStatus *DataStatus) error {
	writeWal := func(wal *WalFile) error {
		walFile, err := d.ost.ReadObject(d.storageWalStatusFile(wal.WalSequence) + ".committed")
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
			WalStatus:     WalStatusCommittedStorage,
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
		txn := d.e.Client().Txn(ctx).If(cmp...).Then(then...)
		tresp, err := txn.Commit()
		if err != nil {
			return etcd.FromEtcdError(err)
		}
		if !tresp.Succeeded {
			return errors.Errorf("failed to sync etcd: wal %q already written", wal.WalSequence)
		}
		return nil
	}

	session, err := concurrency.NewSession(d.e.Client(), concurrency.WithTTL(5), concurrency.WithContext(ctx))
	if err != nil {
		return err
	}
	defer session.Close()

	m := concurrency.NewMutex(session, etcdInitEtcdLockKey)

	// TODO(sgotti) find a way to use a trylock so we'll just return if already
	// locked. Currently multiple task updaters will enqueue and start when another
	// finishes (unuseful and consume resources)
	if err := m.Lock(ctx); err != nil {
		return err
	}
	defer func() { _ = m.Unlock(ctx) }()

	mustInit := false

	_, err = d.e.Get(ctx, etcdWalsDataKey, 0)
	if err != nil {
		if err != etcd.ErrKeyNotFound {
			return err
		}
		mustInit = true
	}

	if mustInit {
		d.log.Infof("no data found in etcd, initializing")

		// delete all wals from etcd
		if err := d.deleteEtcd(ctx); err != nil {
			return err
		}
	}

	// Always create changegroup min revision if it doesn't exists
	cmp := []etcdclientv3.Cmp{}
	then := []etcdclientv3.Op{}

	cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.CreateRevision(etcdChangeGroupMinRevisionKey), "=", 0))
	then = append(then, etcdclientv3.OpPut(etcdChangeGroupMinRevisionKey, ""))
	txn := d.e.Client().Txn(ctx).If(cmp...).Then(then...)
	if _, err := txn.Commit(); err != nil {
		return etcd.FromEtcdError(err)
	}

	if !mustInit {
		return nil
	}

	// walsdata not found in etcd

	var firstWal string
	if dataStatus != nil {
		firstWal = dataStatus.WalSequence
	} else {
		dataStatus, err = d.GetLastDataStatus()
		if err != nil && err != ostypes.ErrNotExist {
			return err
		}
		// set the first wal to import in etcd if there's a snapshot. In this way we'll
		// ignore older wals (or wals left after an import)
		if err == nil {
			firstWal = dataStatus.WalSequence
		}
	}

	// if there're some wals in the objectstorage this means etcd has been reset.
	// So take all the wals in committed or checkpointed state starting from the
	// first not checkpointed wal and put them in etcd
	lastCommittedStorageWalsRing := ring.New(100)
	lastCommittedStorageWalElem := lastCommittedStorageWalsRing
	lastCommittedStorageWalSequence := ""
	wroteWals := 0
	for wal := range d.ListOSTWals("") {
		d.log.Debugf("wal: %s", wal)
		if wal.Err != nil {
			return wal.Err
		}

		if wal.WalSequence < firstWal {
			continue
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

	//  insert an empty wal and make it already committedstorage
	walSequence, err := sequence.IncSequence(ctx, d.e, etcdWalSeqKey)
	if err != nil {
		return err
	}

	walDataFileID := uuid.NewV4().String()
	walDataFilePath := d.storageWalDataFile(walDataFileID)
	walKey := etcdWalKey(walSequence.String())

	if err := d.ost.WriteObject(walDataFilePath, bytes.NewReader([]byte{}), 0, true); err != nil {
		return err
	}
	d.log.Debugf("wrote wal file: %s", walDataFilePath)

	walFilePath := d.storageWalStatusFile(walSequence.String())
	d.log.Infof("syncing committed wal %q to storage", walSequence.String())
	header := &WalHeader{
		WalDataFileID:       walDataFileID,
		PreviousWalSequence: lastCommittedStorageWalSequence,
	}
	headerj, err := json.Marshal(header)
	if err != nil {
		return err
	}
	walFileCommittedPath := walFilePath + ".committed"
	if err := d.ost.WriteObject(walFileCommittedPath, bytes.NewReader(headerj), int64(len(headerj)), true); err != nil {
		return err
	}

	lastCommittedStorageWalSequence = walSequence.String()

	walData := &WalData{
		WalSequence:   walSequence.String(),
		WalDataFileID: walDataFileID,
		WalStatus:     WalStatusCommittedStorage,
	}

	walsData := &WalsData{
		LastCommittedWalSequence: lastCommittedStorageWalSequence,
	}

	walDataj, err := json.Marshal(walData)
	if err != nil {
		return err
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
	then = append(then, etcdclientv3.OpPut(walKey, string(walDataj)))
	txn = d.e.Client().Txn(ctx).If(cmp...).Then(then...)
	tresp, err := txn.Commit()
	if err != nil {
		return etcd.FromEtcdError(err)
	}
	if !tresp.Succeeded {
		return errors.Errorf("failed to sync etcd: walsdata already written")
	}

	// force a checkpoint
	if err := d.checkpoint(ctx, true); err != nil {
		return err
	}

	return nil
}
