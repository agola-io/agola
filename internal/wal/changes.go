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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sorintlab/agola/internal/etcd"

	"github.com/pkg/errors"
	etcdclientv3rpc "go.etcd.io/etcd/etcdserver/api/v3rpc/rpctypes"
	"go.etcd.io/etcd/mvcc/mvccpb"
)

type WalChanges struct {
	actions               map[string][]*Action
	puts                  map[string]string
	deletes               map[string]string
	pathsOrdered          []string
	walSeq                string
	revision              int64
	changeGroupsRevisions changeGroupsRevisions
	initialized           bool
	sync.Mutex
}

func NewWalChanges() *WalChanges {
	return &WalChanges{
		actions:               make(map[string][]*Action),
		puts:                  make(map[string]string),
		deletes:               make(map[string]string),
		changeGroupsRevisions: make(changeGroupsRevisions),
	}
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

func (c *WalChanges) curWalSeq() string {
	return c.walSeq
}

func (c *WalChanges) getPut(p string) (string, bool) {
	walseq, ok := c.puts[p]
	return walseq, ok
}

func (c *WalChanges) getDeletesMap() map[string]struct{} {
	dmap := map[string]struct{}{}
	for p := range c.deletes {
		dmap[p] = struct{}{}
	}
	return dmap
}

func (c *WalChanges) getDelete(p string) bool {
	_, ok := c.deletes[p]
	return ok
}

func (c *WalChanges) addPut(p, walseq string, revision int64) {
	delete(c.deletes, p)
	c.puts[p] = walseq

	c.walSeq = walseq
	c.revision = revision
}

func (c *WalChanges) removePut(p string, revision int64) {
	delete(c.puts, p)

	c.revision = revision
}

func (c *WalChanges) addDelete(p, walseq string, revision int64) {
	delete(c.puts, p)
	c.deletes[p] = walseq

	c.walSeq = walseq
	c.revision = revision
}

func (c *WalChanges) removeDelete(p string, revision int64) {
	delete(c.deletes, p)

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

func (c *WalChanges) updatePathsOrdered() {
	c.pathsOrdered = make([]string, len(c.puts))
	i := 0
	for p := range c.puts {
		c.pathsOrdered[i] = p
		i++
	}
	sort.Sort(sort.StringSlice(c.pathsOrdered))
}

func (w *WalManager) applyWalChanges(ctx context.Context, walData *WalData, revision int64) error {
	walDataFilePath := w.storageWalDataFile(walData.WalDataFileID)

	walDataFile, err := w.lts.ReadObject(walDataFilePath)
	if err != nil {
		return errors.Wrapf(err, "failed to read waldata %q", walDataFilePath)
	}
	defer walDataFile.Close()
	dec := json.NewDecoder(walDataFile)

	w.changes.Lock()
	defer w.changes.Unlock()
	for {
		var action *Action

		err := dec.Decode(&action)
		if err == io.EOF {
			// all done
			break
		}
		if err != nil {
			return errors.Wrapf(err, "failed to decode wal file")
		}

		w.applyWalChangesAction(ctx, action, walData.WalSequence, revision)
	}

	w.changes.updatePathsOrdered()

	return nil
}

func (w *WalManager) applyWalChangesAction(ctx context.Context, action *Action, walSequence string, revision int64) {
	dataPath := w.dataToPathFunc(action.DataType, action.ID)
	if dataPath == "" {
		return
	}
	switch action.ActionType {
	case ActionTypePut:
		w.changes.addPut(dataPath, walSequence, revision)

	case ActionTypeDelete:
		w.changes.addDelete(dataPath, walSequence, revision)
	}
	if w.changes.actions[walSequence] == nil {
		w.changes.actions[walSequence] = []*Action{}
	}
	w.changes.actions[walSequence] = append(w.changes.actions[walSequence], action)
}

func (w *WalManager) watcherLoop(ctx context.Context) error {
	for {
		initialized := w.changes.initialized
		if !initialized {
			if err := w.initializeChanges(ctx); err != nil {
				w.log.Errorf("watcher err: %+v", err)
			}
		} else {
			if err := w.watcher(ctx); err != nil {
				w.log.Errorf("watcher err: %+v", err)
			}
		}

		select {
		case <-ctx.Done():
			w.log.Infof("watcher exiting")
			return nil
		default:
		}

		time.Sleep(1 * time.Second)
	}
}

func (w *WalManager) initializeChanges(ctx context.Context) error {
	var revision int64
	var continuation *etcd.ListPagedContinuation
	for {
		listResp, err := w.e.ListPaged(ctx, etcdWalsDir+"/", 0, 10, continuation)
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
			if err := w.applyWalChanges(ctx, walData, revision); err != nil {
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
		listResp, err := w.e.ListPaged(ctx, etcdChangeGroupsDir+"/", 0, 10, continuation)
		if err != nil {
			return err
		}
		resp := listResp.Resp
		continuation = listResp.Continuation

		for _, kv := range resp.Kvs {
			w.changes.Lock()
			changeGroup := path.Base(string(kv.Key))
			w.changes.putChangeGroup(changeGroup, kv.ModRevision)
			w.changes.Unlock()
		}
		if !listResp.HasMore {
			break
		}
	}

	w.changes.Lock()
	w.changes.revision = revision
	w.changes.initialized = true
	w.changes.Unlock()

	return nil
}

func (w *WalManager) watcher(ctx context.Context) error {
	w.changes.Lock()
	revision := w.changes.curRevision()
	w.changes.Unlock()

	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wch := w.e.Watch(wctx, etcdWalBaseDir+"/", revision+1)
	for wresp := range wch {
		if wresp.Canceled {
			err := wresp.Err()
			if err == etcdclientv3rpc.ErrCompacted {
				w.log.Errorf("required events already compacted, reinitializing watcher changes")
				w.changes.Lock()
				w.changes.initialized = false
				w.changes.Unlock()
			}
			return errors.Wrapf(err, "watch error")
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
					if err := w.applyWalChanges(ctx, walData, revision); err != nil {
						return err
					}
				case mvccpb.DELETE:
					walseq := path.Base(string(key))
					w.changes.Lock()
					putsToDelete := []string{}
					deletesToDelete := []string{}
					for p, pwalseq := range w.changes.puts {
						if pwalseq == walseq {
							putsToDelete = append(putsToDelete, p)
						}
					}
					for p, pwalseq := range w.changes.deletes {
						if pwalseq == walseq {
							deletesToDelete = append(deletesToDelete, p)
						}
					}
					for _, p := range putsToDelete {
						w.changes.removePut(p, revision)
					}
					for _, p := range deletesToDelete {
						w.changes.removeDelete(p, revision)
					}

					delete(w.changes.actions, walseq)

					w.changes.updatePathsOrdered()

					w.changes.Unlock()
				}

			case strings.HasPrefix(key, etcdChangeGroupsDir+"/"):
				switch ev.Type {
				case mvccpb.PUT:
					w.changes.Lock()
					changeGroup := strings.TrimPrefix(string(ev.Kv.Key), etcdChangeGroupsDir+"/")
					w.changes.putChangeGroup(changeGroup, ev.Kv.ModRevision)
					w.changes.Unlock()
				case mvccpb.DELETE:
					w.changes.Lock()
					changeGroup := strings.TrimPrefix(string(ev.Kv.Key), etcdChangeGroupsDir+"/")
					w.changes.removeChangeGroup(changeGroup)
					w.changes.Unlock()
				}

			case key == etcdPingKey:
				w.changes.Lock()
				w.changes.putRevision(wresp.Header.Revision)
				w.changes.Unlock()
			}
		}
	}

	return nil
}
