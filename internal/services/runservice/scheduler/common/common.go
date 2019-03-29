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
	"strings"
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

	EtcdLastIndexKey = "lastindex"
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
	StorageRunsDataDir    = path.Join(StorageDataDir, "runsdata")
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

func StorageRunDataFile(runID string) string {
	return path.Join(StorageRunsDataDir, runID)
}

func StorageRunConfigFile(runID string) string {
	return path.Join(StorageRunsConfigDir, runID)
}

func StorageCounterFile(group string) string {
	return path.Join(StorageCountersDir, group)
}

type ConfigType int

const (
	ConfigTypeRun ConfigType = iota + 1
	ConfigTypeRunData
	ConfigTypeRunConfig
	ConfigTypeCounter
)

func PathToTypeID(p string) (ConfigType, string) {
	var configType ConfigType
	switch path.Dir(p) {
	case StorageRunsDir:
		configType = ConfigTypeRun
	case StorageRunsDataDir:
		configType = ConfigTypeRunData
	case StorageRunsConfigDir:
		configType = ConfigTypeRunConfig
	}

	if strings.HasPrefix(p, StorageCountersDir+"/") {
		configType = ConfigTypeCounter
	}

	if configType == 0 {
		panic(fmt.Errorf("cannot determine configtype for path: %q", p))
	}

	return configType, path.Base(p)
}
