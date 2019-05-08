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

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"strings"

	"github.com/sorintlab/agola/internal/datamanager"
	"github.com/sorintlab/agola/internal/etcd"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/services/runservice/common"
	"github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
	etcdclientv3 "go.etcd.io/etcd/clientv3"
)

const (
	MaxChangegroupNameLength = 256
)

func OSTSubGroupsAndGroupTypes(group string) []string {
	h := util.PathHierarchy(group)
	if len(h)%2 != 1 {
		panic(fmt.Errorf("wrong group path %q", group))
	}

	return h
}

func OSTRootGroup(group string) string {
	pl := util.PathList(group)
	if len(pl) < 2 {
		panic(fmt.Errorf("cannot determine root group name, wrong group path %q", group))
	}

	return pl[1]
}

func OSTSubGroups(group string) []string {
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

func OSTSubGroupTypes(group string) []string {
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

func OSTUpdateRunCounterAction(ctx context.Context, c uint64, group string) (*datamanager.Action, error) {
	// use the first group dir after the root
	pl := util.PathList(group)
	if len(pl) < 2 {
		return nil, errors.Errorf("cannot determine group counter name, wrong group path %q", group)
	}

	cj, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	action := &datamanager.Action{
		ActionType: datamanager.ActionTypePut,
		DataType:   string(common.DataTypeRunCounter),
		ID:         pl[1],
		Data:       cj,
	}

	return action, nil
}

func OSTRunTaskLogsBaseDir(rtID string) string {
	return path.Join("logs", rtID)
}

func OSTRunTaskLogsDataDir(rtID string) string {
	return path.Join(OSTRunTaskLogsBaseDir(rtID), "data")
}

func OSTRunTaskLogsRunsDir(rtID string) string {
	return path.Join(OSTRunTaskLogsBaseDir(rtID), "runs")
}

func OSTRunTaskSetupLogPath(rtID string) string {
	return path.Join(OSTRunTaskLogsDataDir(rtID), "setup.log")
}

func OSTRunTaskStepLogPath(rtID string, step int) string {
	return path.Join(OSTRunTaskLogsDataDir(rtID), "steps", fmt.Sprintf("%d.log", step))
}

func OSTRunTaskLogsRunPath(rtID, runID string) string {
	return path.Join(OSTRunTaskLogsRunsDir(rtID), runID)
}

func OSTRunTaskArchivesBaseDir(rtID string) string {
	return path.Join("workspacearchives", rtID)
}

func OSTRunTaskArchivesDataDir(rtID string) string {
	return path.Join(OSTRunTaskArchivesBaseDir(rtID), "data")
}

func OSTRunTaskArchivesRunsDir(rtID string) string {
	return path.Join(OSTRunTaskArchivesBaseDir(rtID), "runs")
}

func OSTRunTaskArchivePath(rtID string, step int) string {
	return path.Join(OSTRunTaskArchivesDataDir(rtID), fmt.Sprintf("%d.tar", step))
}

func OSTRunTaskArchivesRunPath(rtID, runID string) string {
	return path.Join(OSTRunTaskArchivesRunsDir(rtID), runID)
}

func OSTCacheDir() string {
	return "caches"
}

func OSTCachePath(key string) string {
	return path.Join(OSTCacheDir(), fmt.Sprintf("%s.tar", key))
}

func OSTCacheKey(p string) string {
	base := path.Base(p)
	return strings.TrimSuffix(base, path.Ext(base))
}

func OSTGetRunConfig(dm *datamanager.DataManager, runConfigID string) (*types.RunConfig, error) {
	rcf, _, err := dm.ReadObject(string(common.DataTypeRunConfig), runConfigID, nil)
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

func OSTSaveRunConfigAction(rc *types.RunConfig) (*datamanager.Action, error) {
	rcj, err := json.Marshal(rc)
	if err != nil {
		return nil, err
	}

	action := &datamanager.Action{
		ActionType: datamanager.ActionTypePut,
		DataType:   string(common.DataTypeRunConfig),
		ID:         rc.ID,
		Data:       rcj,
	}

	return action, nil
}

func OSTGetRun(dm *datamanager.DataManager, runID string) (*types.Run, error) {
	rf, _, err := dm.ReadObject(string(common.DataTypeRun), runID, nil)
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

func OSTSaveRunAction(r *types.Run) (*datamanager.Action, error) {
	rj, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	action := &datamanager.Action{
		ActionType: datamanager.ActionTypePut,
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
	// check changegroups name
	if cgt != nil {
		for cgName := range cgt.ChangeGroupsRevisions {
			if strings.Contains(cgName, "/") {
				return nil, fmt.Errorf(`changegroup name %q must not contain "/"`, cgName)
			}
			if len(cgName) > MaxChangegroupNameLength {
				return nil, fmt.Errorf("changegroup name %q too long", cgName)
			}
		}
	}

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

func GetRunEtcdOrOST(ctx context.Context, e *etcd.Store, dm *datamanager.DataManager, runID string) (*types.Run, error) {
	r, _, err := GetRun(ctx, e, runID)
	if err != nil && err != etcd.ErrKeyNotFound {
		return nil, err
	}
	if r == nil {
		r, err = OSTGetRun(dm, runID)
		if err != nil && err != objectstorage.ErrNotExist {
			return nil, err
		}
	}

	return r, nil
}
