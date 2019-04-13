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

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"strings"

	"github.com/sorintlab/agola/internal/etcd"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/services/runservice/scheduler/common"
	"github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/util"
	"github.com/sorintlab/agola/internal/wal"

	"github.com/pkg/errors"
	etcdclientv3 "go.etcd.io/etcd/clientv3"
)

func LTSSubGroupsAndGroupTypes(group string) []string {
	h := util.PathHierarchy(group)
	if len(h)%2 != 1 {
		panic(fmt.Errorf("wrong group path %q", group))
	}

	return h
}

func LTSRootGroup(group string) string {
	pl := util.PathList(group)
	if len(pl) < 2 {
		panic(fmt.Errorf("cannot determine root group name, wrong group path %q", group))
	}

	return pl[1]
}

func LTSSubGroups(group string) []string {
	h := util.PathHierarchy(group)
	if len(h)%2 != 1 {
		panic(fmt.Errorf("wrong group path %q", group))
	}

	// remove group types
	sg := []string{}
	for i, g := range h {
		if i%2 == 0 {
			sg = append(sg, g)
		}
	}

	return sg
}

func LTSSubGroupTypes(group string) []string {
	h := util.PathHierarchy(group)
	if len(h)%2 != 1 {
		panic(fmt.Errorf("wrong group path %q", group))
	}

	// remove group names
	sg := []string{}
	for i, g := range h {
		if i%2 == 1 {
			sg = append(sg, g)
		}
	}

	return sg
}

func LTSRunCounterPaths(group, runID string, sortOrder types.SortOrder) []string {
	paths := []string{}
	subGroups := LTSSubGroups(group)
	for _, subGroup := range subGroups {
		paths = append(paths, common.StorageRunCounterFile(subGroup))
	}
	return paths
}

func LTSUpdateRunCounterAction(ctx context.Context, c uint64, group string) (*wal.Action, error) {
	// use the first group dir after the root
	pl := util.PathList(group)
	if len(pl) < 2 {
		return nil, errors.Errorf("cannot determine group counter name, wrong group path %q", group)
	}

	cj, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	action := &wal.Action{
		ActionType: wal.ActionTypePut,
		DataType:   string(common.DataTypeRunCounter),
		ID:         pl[1],
		Data:       cj,
	}

	return action, nil
}

func LTSRunTaskLogsDir(rtID string) string {
	return path.Join("logs", rtID)
}

func LTSRunTaskSetupLogPath(rtID string) string {
	return path.Join(LTSRunTaskLogsDir(rtID), "setup.log")
}

func LTSRunTaskStepLogPath(rtID string, step int) string {
	return path.Join(LTSRunTaskLogsDir(rtID), "steps", fmt.Sprintf("%d.log", step))
}

func LTSRunArchivePath(rtID string, step int) string {
	return path.Join("workspacearchives", fmt.Sprintf("%s/%d.tar", rtID, step))
}

func LTSCacheDir() string {
	return "caches"
}

func LTSCachePath(key string) string {
	return path.Join(LTSCacheDir(), fmt.Sprintf("%s.tar", key))
}

func LTSCacheKey(p string) string {
	base := path.Base(p)
	return strings.TrimSuffix(base, path.Ext(base))
}

func LTSGetRunConfig(wal *wal.WalManager, runConfigID string) (*types.RunConfig, error) {
	runConfigPath := common.StorageRunConfigFile(runConfigID)
	rcf, _, err := wal.ReadObject(runConfigPath, nil)
	if err != nil {
		return nil, err
	}
	defer rcf.Close()
	d := json.NewDecoder(rcf)
	var rc *types.RunConfig
	if err := d.Decode(&rc); err != nil {
		return nil, err
	}

	return rc, nil
}

func LTSSaveRunConfigAction(rc *types.RunConfig) (*wal.Action, error) {
	rcj, err := json.Marshal(rc)
	if err != nil {
		return nil, err
	}

	action := &wal.Action{
		ActionType: wal.ActionTypePut,
		DataType:   string(common.DataTypeRunConfig),
		ID:         rc.ID,
		Data:       rcj,
	}

	return action, nil
}

func LTSGetRun(wal *wal.WalManager, runID string) (*types.Run, error) {
	runPath := common.StorageRunFile(runID)
	rf, _, err := wal.ReadObject(runPath, nil)

	if err != nil {
		return nil, err
	}
	defer rf.Close()
	d := json.NewDecoder(rf)
	var r *types.Run
	if err := d.Decode(&r); err != nil {
		return nil, err
	}

	return r, nil
}

func LTSSaveRunAction(r *types.Run) (*wal.Action, error) {
	rj, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	action := &wal.Action{
		ActionType: wal.ActionTypePut,
		DataType:   string(common.DataTypeRun),
		ID:         r.ID,
		Data:       rj,
	}

	return action, nil
}

func GetExecutor(ctx context.Context, e *etcd.Store, executorID string) (*types.Executor, error) {
	resp, err := e.Get(ctx, common.EtcdExecutorKey(executorID), 0)
	if err != nil {
		return nil, err
	}

	var executor *types.Executor
	kv := resp.Kvs[0]
	if err := json.Unmarshal(kv.Value, &executor); err != nil {
		return nil, err
	}
	executor.Revision = kv.ModRevision

	return executor, nil
}

func GetExecutors(ctx context.Context, e *etcd.Store) ([]*types.Executor, error) {
	resp, err := e.List(ctx, common.EtcdExecutorsDir, "", 0)
	if err != nil {
		return nil, err
	}

	executors := []*types.Executor{}

	for _, kv := range resp.Kvs {
		var executor *types.Executor
		if err := json.Unmarshal(kv.Value, &executor); err != nil {
			return nil, err
		}
		executor.Revision = kv.ModRevision
		executors = append(executors, executor)
	}

	return executors, nil
}

func PutExecutor(ctx context.Context, e *etcd.Store, executor *types.Executor) (*types.Executor, error) {
	executorj, err := json.Marshal(executor)
	if err != nil {
		return nil, err
	}

	resp, err := e.Put(ctx, common.EtcdExecutorKey(executor.ID), executorj, nil)
	if err != nil {
		return nil, err
	}
	executor.Revision = resp.Header.Revision

	return executor, nil
}

func DeleteExecutor(ctx context.Context, e *etcd.Store, executorID string) error {
	return e.Delete(ctx, common.EtcdExecutorKey(executorID))
}

func GetExecutorTask(ctx context.Context, e *etcd.Store, etID string) (*types.ExecutorTask, error) {
	resp, err := e.Get(ctx, common.EtcdTaskKey(etID), 0)
	if err != nil {
		return nil, err
	}

	var et *types.ExecutorTask
	kv := resp.Kvs[0]
	if err := json.Unmarshal(kv.Value, &et); err != nil {
		return nil, err
	}
	et.Revision = kv.ModRevision

	return et, nil
}

func AtomicPutExecutorTask(ctx context.Context, e *etcd.Store, et *types.ExecutorTask) (*types.ExecutorTask, error) {
	etj, err := json.Marshal(et)
	if err != nil {
		return nil, err
	}

	resp, err := e.AtomicPut(ctx, common.EtcdTaskKey(et.ID), etj, et.Revision, nil)
	if err != nil {
		return nil, err
	}
	et.Revision = resp.Header.Revision

	return et, nil
}

func UpdateExecutorTaskStatus(ctx context.Context, e *etcd.Store, et *types.ExecutorTask) (*types.ExecutorTask, error) {
	curEt, err := GetExecutorTask(ctx, e, et.ID)
	if err != nil {
		return nil, err
	}

	//if curET.Revision >= et.Revision {
	//	return nil, errors.Errorf("concurrency exception")
	//}

	curEt.Status = et.Status
	return AtomicPutExecutorTask(ctx, e, curEt)
}

func DeleteExecutorTask(ctx context.Context, e *etcd.Store, etID string) error {
	return e.Delete(ctx, common.EtcdTaskKey(etID))
}

func GetExecutorTasks(ctx context.Context, e *etcd.Store, executorID string) ([]*types.ExecutorTask, error) {
	resp, err := e.List(ctx, common.EtcdTasksDir, "", 0)
	if err != nil {
		return nil, err
	}

	ets := []*types.ExecutorTask{}

	for _, kv := range resp.Kvs {
		var et *types.ExecutorTask
		if err := json.Unmarshal(kv.Value, &et); err != nil {
			return nil, err
		}
		et.Revision = kv.ModRevision
		if et.Status.ExecutorID == executorID {
			ets = append(ets, et)
		}
	}

	return ets, nil
}

func GetExecutorTasksForRun(ctx context.Context, e *etcd.Store, runID string) ([]*types.ExecutorTask, error) {
	r, curRevision, err := GetRun(ctx, e, runID)
	if err != nil {
		return nil, err
	}

	rtIDs := make([]string, len(r.Tasks))
	for rtID, _ := range r.Tasks {
		rtIDs = append(rtIDs, rtID)

	}

	ets := []*types.ExecutorTask{}

	// batch fetch in group of 10 tasks at the same revision
	i := 0
	for i < len(rtIDs) {
		then := []etcdclientv3.Op{}
		c := 0
		for c < 10 && i < len(rtIDs) {
			then = append(then, etcdclientv3.OpGet(common.EtcdTaskKey(rtIDs[i]), etcdclientv3.WithRev(curRevision)))
			c++
			i++
		}

		txn := e.Client().Txn(ctx).Then(then...)
		tresp, err := txn.Commit()
		if err != nil {
			return nil, etcd.FromEtcdError(err)
		}
		for _, resp := range tresp.Responses {
			if len(resp.GetResponseRange().Kvs) == 0 {
				continue
			}
			kv := resp.GetResponseRange().Kvs[0]
			var et *types.ExecutorTask
			if err := json.Unmarshal(kv.Value, &et); err != nil {
				return nil, err
			}
			et.Revision = kv.ModRevision
			ets = append(ets, et)
		}
	}

	return ets, nil
}

func GetRun(ctx context.Context, e *etcd.Store, runID string) (*types.Run, int64, error) {
	resp, err := e.Get(ctx, common.EtcdRunKey(runID), 0)
	if err != nil {
		return nil, 0, err
	}

	var r *types.Run
	kv := resp.Kvs[0]
	if err := json.Unmarshal(kv.Value, &r); err != nil {
		return nil, 0, err
	}
	r.Revision = kv.ModRevision

	return r, resp.Header.Revision, nil
}

func AtomicPutRun(ctx context.Context, e *etcd.Store, r *types.Run, runEvent *common.RunEvent, cgt *types.ChangeGroupsUpdateToken) (*types.Run, error) {
	// insert only if the run as changed
	curRun, _, err := GetRun(ctx, e, r.ID)
	if err != nil && err != etcd.ErrKeyNotFound {
		return nil, err
	}
	if err != etcd.ErrKeyNotFound {
		if curRun.Revision != r.Revision {
			// fast fail path if the run was already updated
			return nil, errors.Errorf("run modified")
		}
		if reflect.DeepEqual(curRun, r) {
			return curRun, nil
		}
	}

	rj, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	hasOptimisticLocking := false

	cmp := []etcdclientv3.Cmp{}
	then := []etcdclientv3.Op{}

	key := common.EtcdRunKey(r.ID)
	if r.Revision > 0 {
		cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.ModRevision(key), "=", r.Revision))
	} else {
		cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.CreateRevision(key), "=", 0))
	}
	then = append(then, etcdclientv3.OpPut(key, string(rj)))

	if cgt != nil {
		for cgName, cgRev := range cgt.ChangeGroupsRevisions {
			hasOptimisticLocking = true

			groupKey := path.Join(common.EtcdChangeGroupsDir, cgName)
			if cgRev > 0 {
				cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.ModRevision(groupKey), "=", cgRev))
			} else {
				cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.CreateRevision(groupKey), "=", 0))
			}
			then = append(then, etcdclientv3.OpPut(groupKey, ""))
		}

		if cgt.CurRevision > 0 {
			hasOptimisticLocking = true
			cmp = append(cmp, etcdclientv3.Compare(etcdclientv3.ModRevision(common.EtcdChangeGroupMinRevisionKey), "<", cgt.CurRevision+common.EtcdChangeGroupMinRevisionRange))
		}
	}

	if runEvent != nil {
		eventj, err := json.Marshal(runEvent)
		if err != nil {
			return nil, err
		}
		then = append(then, etcdclientv3.OpPut(common.EtcdRunEventKey, string(eventj)))
	}

	txn := e.Client().Txn(ctx).If(cmp...).Then(then...)
	tresp, err := txn.Commit()
	if err != nil {
		return nil, etcd.FromEtcdError(err)
	}
	if !tresp.Succeeded {
		if hasOptimisticLocking {
			return nil, errors.Errorf("optimistic locking failed")
		}
		return nil, errors.Errorf("run modified")
	}

	r.Revision = tresp.Responses[0].GetResponsePut().Header.Revision

	return r, nil
}

func DeleteRun(ctx context.Context, e *etcd.Store, runID string) error {
	return e.Delete(ctx, common.EtcdRunKey(runID))
}

func GetRuns(ctx context.Context, e *etcd.Store) ([]*types.Run, error) {
	resp, err := e.List(ctx, common.EtcdRunsDir, "", 0)
	if err != nil {
		return nil, err
	}

	runs := []*types.Run{}

	for _, kv := range resp.Kvs {
		var r *types.Run
		if err := json.Unmarshal(kv.Value, &r); err != nil {
			return nil, err
		}
		r.Revision = kv.ModRevision
		runs = append(runs, r)
	}

	return runs, nil
}

func GetRunEtcdOrLTS(ctx context.Context, e *etcd.Store, wal *wal.WalManager, runID string) (*types.Run, error) {
	r, _, err := GetRun(ctx, e, runID)
	if err != nil && err != etcd.ErrKeyNotFound {
		return nil, err
	}
	if r == nil {
		r, err = LTSGetRun(wal, runID)
		if err != nil && err != objectstorage.ErrNotExist {
			return nil, err
		}
	}

	return r, nil
}
