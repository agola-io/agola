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
	"fmt"
	"path"
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
	EtcdRunsDir             = "runs"
	EtcdRunSequenceKey      = "runsequence"
	EtcdRunEventKey         = "runevents"
	EtcdRunEventSequenceKey = "runeventsequence"

	EtcdChangeGroupsDir           = "changegroups"
	EtcdChangeGroupMinRevisionKey = "changegroupsminrev"

	EtcdExecutorsDir = "executors"
	EtcdTasksDir     = "tasks"
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

const (
	etcdWalsMinRevisionRange = 100
)

func StorageRunFile(runID string) string {
	return path.Join(StorageRunsDir, runID)
}

func StorageRunConfigFile(runID string) string {
	return path.Join(StorageRunsConfigDir, runID)
}

func StorageRunCounterFile(group string) string {
	return path.Join(StorageCountersDir, group)
}

type DataType string

const (
	DataTypeRun        DataType = "run"
	DataTypeRunConfig  DataType = "runconfig"
	DataTypeRunCounter DataType = "runcounter"
)

func DataToPathFunc(dataType string, id string) string {
	switch DataType(dataType) {
	case DataTypeRun:
		return StorageRunFile(id)
	case DataTypeRunConfig:
		return StorageRunConfigFile(id)
	case DataTypeRunCounter:
		return StorageRunCounterFile(id)
	}

	panic(fmt.Errorf("unknown data type %q", dataType))
}
