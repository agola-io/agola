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
	"io/ioutil"
	"os"
	"testing"
	"time"

	slog "github.com/sorintlab/agola/internal/log"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/objectstorage/posix"
	ostypes "github.com/sorintlab/agola/internal/objectstorage/types"
	"github.com/sorintlab/agola/internal/testutil"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)
var log = logger.Sugar()

func setupEtcd(t *testing.T, dir string) *testutil.TestEmbeddedEtcd {
	tetcd, err := testutil.NewTestEmbeddedEtcd(t, logger, dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := tetcd.Start(); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := tetcd.WaitUp(30 * time.Second); err != nil {
		t.Fatalf("error waiting on store up: %v", err)
	}
	return tetcd
}

func shutdownEtcd(tetcd *testutil.TestEmbeddedEtcd) {
	if tetcd.Etcd != nil {
		tetcd.Kill()
	}
}

type noopCheckpointer struct {
}

func (c *noopCheckpointer) Checkpoint(ctx context.Context, action *Action) error {
	return nil
}

func TestEtcdReset(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	etcdDir, err := ioutil.TempDir(dir, "etcd")
	tetcd := setupEtcd(t, etcdDir)
	defer shutdownEtcd(tetcd)

	ctx, cancel := context.WithCancel(context.Background())

	ostDir, err := ioutil.TempDir(dir, "ost")

	ost, err := posix.New(ostDir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	dmConfig := &DataManagerConfig{
		BasePath:        "basepath",
		E:               tetcd.TestEtcd.Store,
		OST:             objectstorage.NewObjStorage(ost, "/"),
		EtcdWalsKeepNum: 10,
		DataTypes:       []string{"datatype01"},
	}
	dm, err := NewDataManager(ctx, logger, dmConfig)
	dmReadyCh := make(chan struct{})

	t.Logf("starting datamanager")
	go dm.Run(ctx, dmReadyCh)
	<-dmReadyCh

	actions := []*Action{
		{
			ActionType: ActionTypePut,
			DataType:   "datatype01",
			Data:       []byte("{}"),
		},
	}

	expectedObjects := []string{}
	for i := 0; i < 20; i++ {
		objectID := fmt.Sprintf("object%02d", i)
		expectedObjects = append(expectedObjects, objectID)
		actions[0].ID = objectID
		if _, err := dm.WriteWal(ctx, actions, nil); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}

	// wait for wal to be committed storage
	time.Sleep(5 * time.Second)

	t.Logf("stopping datamanager")
	cancel()

	t.Logf("stopping etcd")
	// Reset etcd
	shutdownEtcd(tetcd)
	tetcd.WaitDown(10 * time.Second)
	t.Logf("resetting etcd")
	os.RemoveAll(etcdDir)
	t.Logf("starting etcd")
	tetcd = setupEtcd(t, etcdDir)
	defer shutdownEtcd(tetcd)
	if err := tetcd.Start(); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer shutdownEtcd(tetcd)

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	dmConfig = &DataManagerConfig{
		BasePath:        "basepath",
		E:               tetcd.TestEtcd.Store,
		OST:             objectstorage.NewObjStorage(ost, "/"),
		EtcdWalsKeepNum: 10,
		DataTypes:       []string{"datatype01"},
	}
	dm, err = NewDataManager(ctx, logger, dmConfig)
	dmReadyCh = make(chan struct{})

	t.Logf("starting wal")
	go dm.Run(ctx, dmReadyCh)
	<-dmReadyCh

	time.Sleep(5 * time.Second)

	for i := 0; i < 20; i++ {
		objectID := fmt.Sprintf("object%02d", i)
		_, _, err = dm.ReadObject("datatype01", objectID, nil)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}
}

func TestConcurrentUpdate(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	etcdDir, err := ioutil.TempDir(dir, "etcd")
	tetcd := setupEtcd(t, etcdDir)
	defer shutdownEtcd(tetcd)

	ctx := context.Background()

	ostDir, err := ioutil.TempDir(dir, "ost")

	ost, err := posix.New(ostDir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	dmConfig := &DataManagerConfig{
		E:               tetcd.TestEtcd.Store,
		OST:             objectstorage.NewObjStorage(ost, "/"),
		EtcdWalsKeepNum: 10,
		DataTypes:       []string{"datatype01"},
	}
	dm, err := NewDataManager(ctx, logger, dmConfig)

	actions := []*Action{
		{
			ActionType: ActionTypePut,
			ID:         "object01",
			DataType:   "datatype01",
			Data:       []byte("{}"),
		},
	}

	dmReadyCh := make(chan struct{})
	go dm.Run(ctx, dmReadyCh)
	<-dmReadyCh

	time.Sleep(5 * time.Second)

	cgNames := []string{"changegroup01", "changegroup02"}
	cgt, err := dm.GetChangeGroupsUpdateToken(cgNames)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// populate with a wal
	cgt, err = dm.WriteWal(ctx, actions, cgt)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// this must work successfully
	oldcgt := cgt
	cgt, err = dm.WriteWal(ctx, actions, cgt)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// this must fail since we are using the old cgt
	_, err = dm.WriteWal(ctx, actions, oldcgt)
	if err != ErrConcurrency {
		t.Fatalf("expected err: %v, got %v", ErrConcurrency, err)
	}

	oldcgt = cgt
	// this must work successfully
	cgt, err = dm.WriteWal(ctx, actions, cgt)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// this must fail since we are using the old cgt
	_, err = dm.WriteWal(ctx, actions, oldcgt)
	if err != ErrConcurrency {
		t.Fatalf("expected err: %v, got %v", ErrConcurrency, err)
	}
}

func TestWalCleaner(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	etcdDir, err := ioutil.TempDir(dir, "etcd")
	tetcd := setupEtcd(t, etcdDir)
	defer shutdownEtcd(tetcd)

	ctx := context.Background()

	ostDir, err := ioutil.TempDir(dir, "ost")

	ost, err := posix.New(ostDir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	walKeepNum := 10
	dmConfig := &DataManagerConfig{
		E:                    tetcd.TestEtcd.Store,
		OST:                  objectstorage.NewObjStorage(ost, "/"),
		EtcdWalsKeepNum:      walKeepNum,
		DataTypes:            []string{"datatype01"},
		MinCheckpointWalsNum: 1,
	}
	dm, err := NewDataManager(ctx, logger, dmConfig)

	actions := []*Action{
		{
			ActionType: ActionTypePut,
			ID:         "object01",
			DataType:   "datatype01",
			Data:       []byte("{}"),
		},
	}

	dmReadyCh := make(chan struct{})
	go dm.Run(ctx, dmReadyCh)
	<-dmReadyCh

	for i := 0; i < 20; i++ {
		if _, err := dm.WriteWal(ctx, actions, nil); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}

	dm.checkpoint(ctx)
	dm.walCleaner(ctx)

	walsCount := 0
	for range dm.ListEtcdWals(ctx, 0) {
		walsCount++
	}
	if walsCount != walKeepNum {
		t.Fatalf("expected %d wals in etcd, got %d wals", walKeepNum, walsCount)
	}
}

func TestReadObject(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	etcdDir, err := ioutil.TempDir(dir, "etcd")
	tetcd := setupEtcd(t, etcdDir)
	defer shutdownEtcd(tetcd)

	ctx := context.Background()

	ostDir, err := ioutil.TempDir(dir, "ost")
	ost, err := posix.New(ostDir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	dmConfig := &DataManagerConfig{
		E:   tetcd.TestEtcd.Store,
		OST: objectstorage.NewObjStorage(ost, "/"),
		// remove almost all wals to see that they are removed also from changes
		EtcdWalsKeepNum: 1,
		DataTypes:       []string{"datatype01"},
	}
	dm, err := NewDataManager(ctx, logger, dmConfig)

	actions := []*Action{}
	for i := 0; i < 20; i++ {
		actions = append(actions, &Action{
			ActionType: ActionTypePut,
			ID:         fmt.Sprintf("object%d", i),
			DataType:   "datatype01",
			Data:       []byte(fmt.Sprintf(`{ "ID": "%d" }`, i)),
		})
	}

	dmReadyCh := make(chan struct{})
	go dm.Run(ctx, dmReadyCh)
	<-dmReadyCh

	time.Sleep(5 * time.Second)

	// populate with a wal
	_, err = dm.WriteWal(ctx, actions, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// wait for the event to be read
	time.Sleep(500 * time.Millisecond)
	// should read it
	_, _, err = dm.ReadObject("datatype01", "object1", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_, _, err = dm.ReadObject("datatype01", "object19", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	actions = []*Action{}
	for i := 0; i < 10; i++ {
		actions = append(actions, &Action{
			ActionType: ActionTypeDelete,
			ID:         fmt.Sprintf("object%d", i),
			DataType:   "datatype01",
		})
	}

	_, err = dm.WriteWal(ctx, actions, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// wait for the event to be read
	time.Sleep(500 * time.Millisecond)

	// test read from changes (since not checkpoint yet)

	// should not exists
	_, _, err = dm.ReadObject("datatype01", "object1", nil)
	if err != ostypes.ErrNotExist {
		t.Fatalf("expected err %v, got: %v", ostypes.ErrNotExist, err)
	}
	// should exist
	_, _, err = dm.ReadObject("datatype01", "object19", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// do a checkpoint and wal clean
	dm.checkpoint(ctx)
	dm.walCleaner(ctx)

	// wait for the event to be read
	time.Sleep(500 * time.Millisecond)

	// test read from data

	// should not exists
	_, _, err = dm.ReadObject("datatype01", "object1", nil)
	if err != ostypes.ErrNotExist {
		t.Fatalf("expected err %v, got: %v", ostypes.ErrNotExist, err)
	}
	// should exist
	_, _, err = dm.ReadObject("datatype01", "object19", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
}
