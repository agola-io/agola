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

package wal

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	slog "github.com/sorintlab/agola/internal/log"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/testutil"

	"github.com/google/go-cmp/cmp"
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

	ltsDir, err := ioutil.TempDir(dir, "lts")

	lts, err := objectstorage.NewPosixStorage(ltsDir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	walConfig := &WalManagerConfig{
		BasePath:        "basepath",
		E:               tetcd.TestEtcd.Store,
		Lts:             objectstorage.NewObjStorage(lts, "/"),
		EtcdWalsKeepNum: 10,
	}
	wal, err := NewWalManager(ctx, logger, walConfig)
	go wal.Run(ctx)
	time.Sleep(1 * time.Second)

	actions := []*Action{
		{
			ActionType: ActionTypePut,
			Data:       []byte("{}"),
		},
	}

	expectedObjects := []string{}
	for i := 0; i < 20; i++ {
		objectPath := fmt.Sprintf("object%02d", i)
		expectedObjects = append(expectedObjects, objectPath)
		actions[0].Path = objectPath
		if _, err := wal.WriteWal(ctx, actions, nil); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}

	// wait for wal to be committed storage
	time.Sleep(5 * time.Second)

	// Reset etcd
	shutdownEtcd(tetcd)
	tetcd.WaitDown(10 * time.Second)
	os.RemoveAll(etcdDir)
	if err := tetcd.Start(); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer shutdownEtcd(tetcd)

	cancel()
	ctx = context.Background()
	go wal.Run(ctx)
	time.Sleep(5 * time.Second)

	curObjects := []string{}
	doneCh := make(chan struct{})
	for object := range wal.List("", "", true, doneCh) {
		t.Logf("path: %q", object.Path)
		if object.Err != nil {
			t.Fatalf("unexpected err: %v", object.Err)
		}
		curObjects = append(curObjects, object.Path)
	}
	close(doneCh)
	t.Logf("curObjects: %s", curObjects)

	if diff := cmp.Diff(expectedObjects, curObjects); diff != "" {
		t.Error(diff)
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

	ltsDir, err := ioutil.TempDir(dir, "lts")

	lts, err := objectstorage.NewPosixStorage(ltsDir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	walConfig := &WalManagerConfig{
		E:               tetcd.TestEtcd.Store,
		Lts:             objectstorage.NewObjStorage(lts, "/"),
		EtcdWalsKeepNum: 10,
	}
	wal, err := NewWalManager(ctx, logger, walConfig)

	actions := []*Action{
		{
			ActionType: ActionTypePut,
			Path:       "/object01",
			Data:       []byte("{}"),
		},
	}

	go wal.Run(ctx)
	time.Sleep(1 * time.Second)

	cgNames := []string{"changegroup01", "changegroup02"}
	cgt := wal.GetChangeGroupsUpdateToken(cgNames)

	// populate with a wal
	cgt, err = wal.WriteWal(ctx, actions, cgt)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// this must work successfully
	oldcgt := cgt
	cgt, err = wal.WriteWal(ctx, actions, cgt)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// this must fail since we are using the old cgt
	_, err = wal.WriteWal(ctx, actions, oldcgt)
	if err != ErrConcurrency {
		t.Fatalf("expected err: %v, got %v", ErrConcurrency, err)
	}

	oldcgt = cgt
	// this must work successfully
	cgt, err = wal.WriteWal(ctx, actions, cgt)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// this must fail since we are using the old cgt
	_, err = wal.WriteWal(ctx, actions, oldcgt)
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

	ltsDir, err := ioutil.TempDir(dir, "lts")

	lts, err := objectstorage.NewPosixStorage(ltsDir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	walKeepNum := 10
	walConfig := &WalManagerConfig{
		E:               tetcd.TestEtcd.Store,
		Lts:             objectstorage.NewObjStorage(lts, "/"),
		EtcdWalsKeepNum: walKeepNum,
	}
	wal, err := NewWalManager(ctx, logger, walConfig)

	actions := []*Action{
		{
			ActionType: ActionTypePut,
			Path:       "/object01",
			Data:       []byte("{}"),
		},
	}

	go wal.Run(ctx)
	time.Sleep(1 * time.Second)

	for i := 0; i < 20; i++ {
		if _, err := wal.WriteWal(ctx, actions, nil); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}

	// wait for walCleaner to complete
	time.Sleep(5 * time.Second)

	walsCount := 0
	for range wal.ListEtcdWals(ctx, 0) {
		walsCount++
	}
	if walsCount != walKeepNum {
		t.Fatalf("expected %d wals in etcd, got %d wals", walKeepNum, walsCount)
	}
}
