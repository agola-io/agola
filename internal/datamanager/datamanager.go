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
	"fmt"
	"path"
	"strings"
	"time"

	"agola.io/agola/internal/etcd"
	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/sequence"

	"go.uber.org/zap"
	errors "golang.org/x/xerrors"
)

// TODO(sgotti) handle etcd unwanted changes:
// * Etcd cluster rebuild: we cannot rely on etcd header ClusterID since it could be the same as it's generated using the listen urls. We should add our own clusterid key and use it.
// * Etcd cluster restored to a previous revision: really bad cause should detect that the revision is smaller than the current one

const (
	DefaultSyncInterval                = 5 * time.Second
	DefaultCheckpointInterval          = 10 * time.Second
	DefaultCheckpointCleanInterval     = 5 * time.Minute
	DefaultEtcdWalCleanInterval        = 2 * time.Second
	DefaultStorageWalCleanInterval     = 5 * time.Minute
	DefaultCompactChangeGroupsInterval = 1 * time.Second
	DefaultEtcdPingerInterval          = 1 * time.Second
	DefaultEtcdWalsKeepNum             = 100
	DefaultMinCheckpointWalsNum        = 100
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
	etcdCheckpointSeqKey              = path.Join(etcdWalBaseDir, "checkpointseq")

	etcdInitEtcdLockKey            = path.Join(etcdWalBaseDir, "initetcd")
	etcdSyncLockKey                = path.Join(etcdWalBaseDir, "synclock")
	etcdCompactChangeGroupsLockKey = path.Join(etcdWalBaseDir, "compactchangegroupslock")
	etcdCheckpointLockKey          = path.Join(etcdWalBaseDir, "checkpointlock")
	etcdWalCleanerLockKey          = path.Join(etcdWalBaseDir, "walcleanerlock")
	etcdStorageWalCleanerLockKey   = path.Join(etcdWalBaseDir, "storagewalcleanerlock")

	etcdChangeGroupsDir           = path.Join(etcdWalBaseDir, "changegroups")
	etcdChangeGroupMinRevisionKey = path.Join(etcdWalBaseDir, "changegroupsminrev")

	etcdPingKey = path.Join(etcdWalBaseDir, "ping")
)

const (
	etcdChangeGroupMinRevisionRange = 1000

	maxChangegroupNameLength = 256
)

type DataManagerConfig struct {
	BasePath                string
	E                       *etcd.Store
	OST                     *objectstorage.ObjStorage
	DataTypes               []string
	EtcdWalsKeepNum         int
	CheckpointInterval      time.Duration
	CheckpointCleanInterval time.Duration
	// MinCheckpointWalsNum is the minimum number of wals required before doing a checkpoint
	MinCheckpointWalsNum int
	MaxDataFileSize      int64
	MaintenanceMode      bool
}

type DataManager struct {
	basePath                string
	log                     *zap.SugaredLogger
	e                       *etcd.Store
	ost                     *objectstorage.ObjStorage
	changes                 *WalChanges
	dataTypes               []string
	etcdWalsKeepNum         int
	checkpointInterval      time.Duration
	checkpointCleanInterval time.Duration
	minCheckpointWalsNum    int
	maxDataFileSize         int64
	maintenanceMode         bool
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
	if conf.CheckpointCleanInterval == 0 {
		conf.CheckpointCleanInterval = DefaultCheckpointCleanInterval
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
		basePath:                conf.BasePath,
		log:                     logger.Sugar(),
		e:                       conf.E,
		ost:                     conf.OST,
		changes:                 NewWalChanges(conf.DataTypes),
		dataTypes:               conf.DataTypes,
		etcdWalsKeepNum:         conf.EtcdWalsKeepNum,
		checkpointInterval:      conf.CheckpointInterval,
		checkpointCleanInterval: conf.CheckpointCleanInterval,
		minCheckpointWalsNum:    conf.MinCheckpointWalsNum,
		maxDataFileSize:         conf.MaxDataFileSize,
		maintenanceMode:         conf.MaintenanceMode,
	}

	// add trailing slash the basepath
	if d.basePath != "" && !strings.HasSuffix(d.basePath, "/") {
		d.basePath = d.basePath + "/"
	}

	return d, nil
}

func (d *DataManager) storageWalStatusDir() string {
	return path.Join(d.basePath, storageWalsStatusDir)
}

func (d *DataManager) storageWalStatusFile(walSeq string) string {
	return path.Join(d.storageWalStatusDir(), walSeq)
}

func (d *DataManager) storageWalDataDir() string {
	return path.Join(d.basePath, storageWalsDataDir)
}

func (d *DataManager) storageWalDataFile(walFileID string) string {
	return path.Join(d.storageWalDataDir(), walFileID)
}

func (d *DataManager) storageDataDir() string {
	return path.Join(d.basePath, storageDataDir)
}

func (d *DataManager) dataStatusPath(sequence *sequence.Sequence) string {
	return fmt.Sprintf("%s/%s.status", d.storageDataDir(), sequence)
}

func (d *DataManager) DataTypeDir(dataType string) string {
	return fmt.Sprintf("%s/%s", d.storageDataDir(), dataType)
}

func (d *DataManager) DataFileBasePath(dataType, name string) string {
	return fmt.Sprintf("%s/%s", d.DataTypeDir(dataType), name)
}

func (d *DataManager) DataFileIndexPath(dataType, name string) string {
	return fmt.Sprintf("%s.index", d.DataFileBasePath(dataType, name))
}

func (d *DataManager) DataFilePath(dataType, name string) string {
	return fmt.Sprintf("%s.data", d.DataFileBasePath(dataType, name))
}

func etcdWalKey(walSeq string) string {
	return path.Join(etcdWalsDir, walSeq)
}

// SetMaintenanceMode sets the datamanager in maintenance mode. This method must
// be called before invoking the Run method
func (d *DataManager) SetMaintenanceMode(maintenanceMode bool) {
	d.maintenanceMode = maintenanceMode
}

// deleteEtcd deletes all etcd data excluding keys used for locking
func (d *DataManager) deleteEtcd(ctx context.Context) error {
	prefixes := []string{
		etcdWalsDir + "/",
		etcdWalsDataKey,
		etcdWalSeqKey,
		etcdLastCommittedStorageWalSeqKey,
		etcdCheckpointSeqKey,
		etcdChangeGroupsDir + "/",
		etcdChangeGroupMinRevisionKey,
	}
	for _, prefix := range prefixes {
		if err := d.e.DeletePrefix(ctx, prefix); err != nil {
			return err
		}
	}

	return nil
}

func (d *DataManager) Run(ctx context.Context, readyCh chan struct{}) error {
	if !d.maintenanceMode {
		for {
			err := d.InitEtcd(ctx, nil)
			if err == nil {
				break
			}
			d.log.Errorf("failed to initialize etcd: %+v", err)

			sleepCh := time.NewTimer(1 * time.Second).C
			select {
			case <-ctx.Done():
				return nil
			case <-sleepCh:
			}
		}

		readyCh <- struct{}{}

		go d.watcherLoop(ctx)
		go d.syncLoop(ctx)
		go d.checkpointLoop(ctx)
		go d.checkpointCleanLoop(ctx)
		go d.etcdWalCleanerLoop(ctx)
		go d.storageWalCleanerLoop(ctx)
		go d.compactChangeGroupsLoop(ctx)
		go d.etcdPingerLoop(ctx)

	} else {
		d.log.Infof("datamanager starting in maintenance mode")
		readyCh <- struct{}{}
	}

	<-ctx.Done()
	d.log.Infof("datamanager exiting")

	return nil
}
