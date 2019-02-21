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
