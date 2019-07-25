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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"time"

	"agola.io/agola/internal/etcd"

	etcdclientv3rpc "go.etcd.io/etcd/etcdserver/api/v3rpc/rpctypes"
	"go.etcd.io/etcd/mvcc/mvccpb"
	errors "golang.org/x/xerrors"
)

// TODO(sgotti) rewrite this to use a sqlite local cache

type WalChanges struct {
	actions               map[string][]*Action
	puts                  map[string]map[string]string // map[dataType]map[id]
	deletes               map[string]map[string]string
	walSeq                string
	revision              int64
	changeGroupsRevisions changeGroupsRevisions
	initialized           bool
	sync.Mutex
}

func NewWalChanges(dataTypes []string) *WalChanges {
	changes := &WalChanges{
		actions:               make(map[string][]*Action),
		puts:                  make(map[string]map[string]string),
		deletes:               make(map[string]map[string]string),
		changeGroupsRevisions: make(changeGroupsRevisions),
	}

	for _, dataType := range dataTypes {
		changes.puts[dataType] = make(map[string]string)
		changes.deletes[dataType] = make(map[string]string)
	}

	return changes
}

func (c *WalChanges) String() string {
	return fmt.Sprintf("puts: %s, deletes: %s, walSeq: %s, revision: %d, initialized: %t", c.puts, c.deletes, c.walSeq, c.revision, c.initialized)
}

func (c *WalChanges) curRevision() int64 {
	return c.revision
}

func (c *WalChanges) putRevision(revision int64) {
	c.revision = revision
}

func (c *WalChanges) getPut(dataType, id string) (string, bool) {
	walseq, ok := c.puts[dataType][id]
	return walseq, ok
}

func (c *WalChanges) addPut(dataType, id, walseq string, revision int64) {
	delete(c.deletes[dataType], id)
	c.puts[dataType][id] = walseq

	c.walSeq = walseq
	c.revision = revision
}

func (c *WalChanges) removePut(dataType, id string, revision int64) {
	delete(c.puts[dataType], id)

	c.revision = revision
}

func (c *WalChanges) addDelete(dataType, id, walseq string, revision int64) {
	delete(c.puts[dataType], id)
	c.deletes[dataType][id] = walseq

	c.walSeq = walseq
	c.revision = revision
}

func (c *WalChanges) removeDelete(dataType, id string, revision int64) {
	delete(c.deletes[dataType], id)

	c.revision = revision
}

func (c *WalChanges) getChangeGroups(cgNames []string) changeGroupsRevisions {
	cgr := map[string]int64{}
	for _, cgName := range cgNames {
		if rev, ok := c.changeGroupsRevisions[cgName]; ok {
			cgr[cgName] = rev
		} else {
			// for non existing changegroups use a changegroup with revision = 0
			cgr[cgName] = 0
		}
	}

	return cgr
}

func (c *WalChanges) putChangeGroup(cgName string, cgRev int64) {
	c.changeGroupsRevisions[cgName] = cgRev
}

func (c *WalChanges) removeChangeGroup(cgName string) {
	delete(c.changeGroupsRevisions, cgName)
}

func (d *DataManager) applyWalChanges(ctx context.Context, walData *WalData, revision int64) error {
	walDataFilePath := d.storageWalDataFile(walData.WalDataFileID)

	walDataFile, err := d.ost.ReadObject(walDataFilePath)
	if err != nil {
		return errors.Errorf("failed to read waldata %q: %w", walDataFilePath, err)
	}
	defer walDataFile.Close()
	dec := json.NewDecoder(walDataFile)

	d.changes.Lock()
	defer d.changes.Unlock()
	for {
		var action *Action

		err := dec.Decode(&action)
		if err == io.EOF {
			// all done
			break
		}
		if err != nil {
			return errors.Errorf("failed to decode wal file: %w", err)
		}

		d.applyWalChangesAction(ctx, action, walData.WalSequence, revision)
	}

	return nil
}

func (d *DataManager) applyWalChangesAction(ctx context.Context, action *Action, walSequence string, revision int64) {
	switch action.ActionType {
	case ActionTypePut:
		d.changes.addPut(action.DataType, action.ID, walSequence, revision)

	case ActionTypeDelete:
		d.changes.addDelete(action.DataType, action.ID, walSequence, revision)
	}
	if d.changes.actions[walSequence] == nil {
		d.changes.actions[walSequence] = []*Action{}
	}
	d.changes.actions[walSequence] = append(d.changes.actions[walSequence], action)
}

func (d *DataManager) watcherLoop(ctx context.Context) {
	for {
		initialized := d.changes.initialized
		if !initialized {
			if err := d.initializeChanges(ctx); err != nil {
				d.log.Errorf("watcher err: %+v", err)
			}
		} else {
			if err := d.watcher(ctx); err != nil {
				d.log.Errorf("watcher err: %+v", err)
			}
		}

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			d.log.Infof("watcher exiting")
			return
		case <-sleepCh:
		}
	}
}

func (d *DataManager) initializeChanges(ctx context.Context) error {
	var revision int64
	var continuation *etcd.ListPagedContinuation
	for {
		listResp, err := d.e.ListPaged(ctx, etcdWalsDir+"/", 0, 10, continuation)
		if err != nil {
			return err
		}
		resp := listResp.Resp
		continuation = listResp.Continuation

		revision = resp.Header.Revision

		for _, kv := range resp.Kvs {
			var walData *WalData
			if err := json.Unmarshal(kv.Value, &walData); err != nil {
				return err
			}
			if err := d.applyWalChanges(ctx, walData, revision); err != nil {
				return err
			}
		}
		if !listResp.HasMore {
			break
		}
	}

	continuation = nil
	// use the same revision
	for {
		listResp, err := d.e.ListPaged(ctx, etcdChangeGroupsDir+"/", 0, 10, continuation)
		if err != nil {
			return err
		}
		resp := listResp.Resp
		continuation = listResp.Continuation

		for _, kv := range resp.Kvs {
			d.changes.Lock()
			changeGroup := path.Base(string(kv.Key))
			d.changes.putChangeGroup(changeGroup, kv.ModRevision)
			d.changes.Unlock()
		}
		if !listResp.HasMore {
			break
		}
	}

	d.changes.Lock()
	d.changes.revision = revision
	d.changes.initialized = true
	d.changes.Unlock()

	return nil
}

func (d *DataManager) watcher(ctx context.Context) error {
	d.changes.Lock()
	revision := d.changes.curRevision()
	d.changes.Unlock()

	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wch := d.e.Watch(wctx, etcdWalBaseDir+"/", revision+1)
	for wresp := range wch {
		if wresp.Canceled {
			err := wresp.Err()
			if err == etcdclientv3rpc.ErrCompacted {
				d.log.Errorf("required events already compacted, reinitializing watcher changes")
				d.changes.Lock()
				d.changes.initialized = false
				d.changes.Unlock()
			}
			return errors.Errorf("watch error: %w", err)
		}
		revision := wresp.Header.Revision

		for _, ev := range wresp.Events {
			key := string(ev.Kv.Key)

			switch {
			case strings.HasPrefix(key, etcdWalsDir+"/"):
				switch ev.Type {
				case mvccpb.PUT:
					var walData *WalData
					if err := json.Unmarshal(ev.Kv.Value, &walData); err != nil {
						return err
					}
					if walData.WalStatus != WalStatusCommitted {
						continue
					}
					if err := d.applyWalChanges(ctx, walData, revision); err != nil {
						return err
					}
				case mvccpb.DELETE:
					walseq := path.Base(string(key))
					d.changes.Lock()
					putsToDelete := map[string][]string{}
					deletesToDelete := map[string][]string{}
					for _, dataType := range d.dataTypes {
						putsToDelete[dataType] = []string{}
						deletesToDelete[dataType] = []string{}
					}
					for _, dataType := range d.dataTypes {
						for p, pwalseq := range d.changes.puts[dataType] {
							if pwalseq == walseq {
								putsToDelete[dataType] = append(putsToDelete[dataType], p)
							}
						}
					}
					for _, dataType := range d.dataTypes {
						for id, pwalseq := range d.changes.deletes[dataType] {
							if pwalseq == walseq {
								deletesToDelete[dataType] = append(deletesToDelete[dataType], id)
							}
						}
					}
					for dataType, ids := range putsToDelete {
						for _, id := range ids {
							d.changes.removePut(dataType, id, revision)
						}
					}
					for dataType, ids := range putsToDelete {
						for _, id := range ids {
							d.changes.removeDelete(dataType, id, revision)
						}
					}

					delete(d.changes.actions, walseq)

					d.changes.Unlock()
				}

			case strings.HasPrefix(key, etcdChangeGroupsDir+"/"):
				switch ev.Type {
				case mvccpb.PUT:
					d.changes.Lock()
					changeGroup := strings.TrimPrefix(string(ev.Kv.Key), etcdChangeGroupsDir+"/")
					d.changes.putChangeGroup(changeGroup, ev.Kv.ModRevision)
					d.changes.Unlock()
				case mvccpb.DELETE:
					d.changes.Lock()
					changeGroup := strings.TrimPrefix(string(ev.Kv.Key), etcdChangeGroupsDir+"/")
					d.changes.removeChangeGroup(changeGroup)
					d.changes.Unlock()
				}

			case key == etcdPingKey:
				d.changes.Lock()
				d.changes.putRevision(wresp.Header.Revision)
				d.changes.Unlock()
			}
		}
	}

	return nil
}
