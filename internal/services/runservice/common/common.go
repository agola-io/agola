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

package common

import (
	"path"
)

const (
	MaxCacheKeyLength = 200
)

type ErrNotExist struct {
	err error
}

func NewErrNotExist(err error) error {
	return ErrNotExist{err: err}
}

func (e ErrNotExist) Error() string {
	return e.err.Error()
}

var (
	EtcdSchedulerBaseDir = "scheduler"

	EtcdRunsDir             = path.Join(EtcdSchedulerBaseDir, "runs")
	EtcdRunSequenceKey      = path.Join(EtcdSchedulerBaseDir, "runsequence")
	EtcdRunEventKey         = path.Join(EtcdSchedulerBaseDir, "runevents")
	EtcdRunEventSequenceKey = path.Join(EtcdSchedulerBaseDir, "runeventsequence")

	EtcdChangeGroupsDir           = path.Join(EtcdSchedulerBaseDir, "changegroups")
	EtcdChangeGroupMinRevisionKey = path.Join(EtcdSchedulerBaseDir, "changegroupsminrev")

	EtcdExecutorsDir = path.Join(EtcdSchedulerBaseDir, "executors")
	EtcdTasksDir     = path.Join(EtcdSchedulerBaseDir, "tasks")

	EtcdPingKey = path.Join(EtcdSchedulerBaseDir, "ping")

	EtcdCompactChangeGroupsLockKey = path.Join(EtcdSchedulerBaseDir, "compactchangegroupslock")
	EtcdCacheCleanerLockKey        = path.Join(EtcdSchedulerBaseDir, "locks", "cachecleaner")
	EtcdWorkspaceCleanerLockKey    = path.Join(EtcdSchedulerBaseDir, "locks", "workspacecleaner")
	EtcdTaskUpdaterLockKey         = path.Join(EtcdSchedulerBaseDir, "locks", "taskupdater")

	EtcdMaintenanceKey = "maintenance"
)

func EtcdRunKey(runID string) string       { return path.Join(EtcdRunsDir, runID) }
func EtcdExecutorKey(taskID string) string { return path.Join(EtcdExecutorsDir, taskID) }
func EtcdTaskKey(taskID string) string     { return path.Join(EtcdTasksDir, taskID) }

const (
	EtcdChangeGroupMinRevisionRange = 100
)

var (
	StorageDataDir        = ""
	StorageRunsDir        = path.Join(StorageDataDir, "runs")
	StorageRunsConfigDir  = path.Join(StorageDataDir, "runsconfig")
	StorageRunsIndexesDir = path.Join(StorageDataDir, "runsindexes")
	StorageCountersDir    = path.Join(StorageDataDir, "counters")
)

type DataType string

const (
	DataTypeRun        DataType = "run"
	DataTypeRunConfig  DataType = "runconfig"
	DataTypeRunCounter DataType = "runcounter"
)
