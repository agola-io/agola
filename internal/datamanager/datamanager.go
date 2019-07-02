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
	"path"
	"strings"
	"time"

	"agola.io/agola/internal/etcd"
	"agola.io/agola/internal/objectstorage"

	"go.uber.org/zap"
	errors "golang.org/x/xerrors"
)

// TODO(sgotti) handle etcd unwanted changes:
// * Etcd cluster rebuild: we cannot rely on etcd header ClusterID since it could be the same as it's generated using the listen urls. We should add our own clusterid key and use it.
// * Etcd cluster restored to a previous revision: really bad cause should detect that the revision is smaller than the current one

// Storage paths
// wals/{walSeq}
//
// Etcd paths
// wals/{walSeq}

const (
	DefaultCheckpointInterval   = 10 * time.Second
	DefaultEtcdWalsKeepNum      = 100
	DefaultMinCheckpointWalsNum = 100
)

var (
	ErrCompacted   = errors.New("required revision has been compacted")
	ErrConcurrency = errors.New("wal concurrency error: change groups already updated")
)

var (
	// Storage paths. Always use path (not filepath) to use the "/" separator
	storageDataDir = "data"

	storageWalsDir       = "wals"
	storageWalsStatusDir = path.Join(storageWalsDir, "status")
	storageWalsDataDir   = path.Join(storageWalsDir, "data")

	// etcd paths. Always use path (not filepath) to use the "/" separator
	etcdWalBaseDir                    = "datamanager"
	etcdWalsDir                       = path.Join(etcdWalBaseDir, "wals")
	etcdWalsDataKey                   = path.Join(etcdWalBaseDir, "walsdata")
	etcdWalSeqKey                     = path.Join(etcdWalBaseDir, "walseq")
	etcdLastCommittedStorageWalSeqKey = path.Join(etcdWalBaseDir, "lastcommittedstoragewalseq")

	etcdCheckpointSeqKey = path.Join(etcdWalBaseDir, "checkpointseq")

	etcdSyncLockKey       = path.Join(etcdWalBaseDir, "synclock")
	etcdCheckpointLockKey = path.Join(etcdWalBaseDir, "checkpointlock")
	etcdWalCleanerLockKey = path.Join(etcdWalBaseDir, "walcleanerlock")

	etcdChangeGroupsDir           = path.Join(etcdWalBaseDir, "changegroups")
	etcdChangeGroupMinRevisionKey = path.Join(etcdWalBaseDir, "changegroupsminrev")

	etcdPingKey = path.Join(etcdWalBaseDir, "ping")
)

const (
	etcdChangeGroupMinRevisionRange = 1000

	maxChangegroupNameLength = 256
)

type DataManagerConfig struct {
	BasePath           string
	E                  *etcd.Store
	OST                *objectstorage.ObjStorage
	DataTypes          []string
	EtcdWalsKeepNum    int
	CheckpointInterval time.Duration
	// MinCheckpointWalsNum is the minimum number of wals required before doing a checkpoint
	MinCheckpointWalsNum int
	MaxDataFileSize      int64
}

type DataManager struct {
	basePath             string
	log                  *zap.SugaredLogger
	e                    *etcd.Store
	ost                  *objectstorage.ObjStorage
	changes              *WalChanges
	dataTypes            []string
	etcdWalsKeepNum      int
	checkpointInterval   time.Duration
	minCheckpointWalsNum int
	maxDataFileSize      int64
}

func NewDataManager(ctx context.Context, logger *zap.Logger, conf *DataManagerConfig) (*DataManager, error) {
	if conf.EtcdWalsKeepNum == 0 {
		conf.EtcdWalsKeepNum = DefaultEtcdWalsKeepNum
	}
	if conf.EtcdWalsKeepNum < 1 {
		return nil, errors.New("etcdWalsKeepNum must be greater than 0")
	}
	if conf.CheckpointInterval == 0 {
		conf.CheckpointInterval = DefaultCheckpointInterval
	}
	if conf.MinCheckpointWalsNum == 0 {
		conf.MinCheckpointWalsNum = DefaultMinCheckpointWalsNum
	}
	if conf.MinCheckpointWalsNum < 1 {
		return nil, errors.New("minCheckpointWalsNum must be greater than 0")
	}
	if conf.MaxDataFileSize == 0 {
		conf.MaxDataFileSize = DefaultMaxDataFileSize
	}

	d := &DataManager{
		basePath:             conf.BasePath,
		log:                  logger.Sugar(),
		e:                    conf.E,
		ost:                  conf.OST,
		changes:              NewWalChanges(conf.DataTypes),
		dataTypes:            conf.DataTypes,
		etcdWalsKeepNum:      conf.EtcdWalsKeepNum,
		checkpointInterval:   conf.CheckpointInterval,
		minCheckpointWalsNum: conf.MinCheckpointWalsNum,
		maxDataFileSize:      conf.MaxDataFileSize,
	}

	// add trailing slash the basepath
	if d.basePath != "" && !strings.HasSuffix(d.basePath, "/") {
		d.basePath = d.basePath + "/"
	}

	return d, nil
}

func (d *DataManager) Run(ctx context.Context, readyCh chan struct{}) error {
	for {
		err := d.InitEtcd(ctx)
		if err == nil {
			break
		}
		d.log.Errorf("failed to initialize etcd: %+v", err)
		time.Sleep(1 * time.Second)
	}

	readyCh <- struct{}{}

	go d.watcherLoop(ctx)
	go d.syncLoop(ctx)
	go d.checkpointLoop(ctx)
	go d.walCleanerLoop(ctx)
	go d.compactChangeGroupsLoop(ctx)
	go d.etcdPingerLoop(ctx)

	<-ctx.Done()
	d.log.Infof("walmanager exiting")

	return nil
}
