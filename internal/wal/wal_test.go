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
	walReadyCh := make(chan struct{})
	go wal.Run(ctx, walReadyCh)
	<-walReadyCh

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
	go wal.Run(ctx, walReadyCh)
	<-walReadyCh

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

	walReadyCh := make(chan struct{})
	go wal.Run(ctx, walReadyCh)
	<-walReadyCh

	cgNames := []string{"changegroup01", "changegroup02"}
	cgt, err := wal.GetChangeGroupsUpdateToken(cgNames)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// populate with a wal
	cgt, err = wal.WriteWal(ctx, actions, cgt)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// this must work successfully
	oldcgt := cgt
	cgt, err = wal.WriteWal(ctx, actions, cgt)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// this must fail since we are using the old cgt
	_, err = wal.WriteWal(ctx, actions, oldcgt)
	if err != ErrConcurrency {
		t.Fatalf("expected err: %v, got %v", ErrConcurrency, err)
	}

	// this must work successfully
	cgt, err = wal.WriteWal(ctx, actions, cgt)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// this must fail since we are using the old cgt
	oldcgt = cgt
	cgt, err = wal.WriteWal(ctx, actions, cgt)
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

	walReadyCh := make(chan struct{})
	go wal.Run(ctx, walReadyCh)
	<-walReadyCh

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
