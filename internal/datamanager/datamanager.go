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

package datamanager

import (
	"context"
	"path"
	"strings"
	"time"

	"github.com/sorintlab/agola/internal/etcd"
	"github.com/sorintlab/agola/internal/objectstorage"

	"github.com/pkg/errors"
	"go.uber.org/zap"
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
	DefaultCheckpointInterval   = 1 * time.Minute
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

	select {
	case <-ctx.Done():
		d.log.Infof("walmanager exiting")
		return nil
	}
}
