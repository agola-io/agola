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

	EtcdCacheCleanerLockKey = path.Join(EtcdSchedulerBaseDir, "locks", "cachecleaner")
	EtcdTaskUpdaterLockKey  = path.Join(EtcdSchedulerBaseDir, "locks", "taskupdater")
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

type DataType string

const (
	DataTypeRun        DataType = "run"
	DataTypeRunConfig  DataType = "runconfig"
	DataTypeRunCounter DataType = "runcounter"
)
