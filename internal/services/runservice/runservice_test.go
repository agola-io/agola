// Copyright 2022 Sorint.lab
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

package runservice

import (
	"bytes"
	"context"
	"io/ioutil"
	"net"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/runservice/action"
	"agola.io/agola/internal/sql"
	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/runservice/types"

	"github.com/rs/zerolog"
)

func setupRunservice(ctx context.Context, t *testing.T, log zerolog.Logger, dir string) *Runservice {
	listenAddress, port, err := testutil.GetFreePort(true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	ostDir, err := ioutil.TempDir(dir, "ost")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	rsDir, err := ioutil.TempDir(dir, "rs")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	baseConfig := config.Runservice{
		DB: config.DB{
			Type:       sql.Sqlite3,
			ConnString: filepath.Join(dir, "db"),
		},
		ObjectStorage: config.ObjectStorage{
			Type: config.ObjectStorageTypePosix,
			Path: ostDir,
		},
		Web: config.Web{},
	}
	rsConfig := baseConfig
	rsConfig.DataDir = rsDir
	rsConfig.Web.ListenAddress = net.JoinHostPort(listenAddress, port)

	rs, err := NewRunservice(ctx, log, &rsConfig)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	return rs
}

func getRuns(ctx context.Context, rs *Runservice) ([]*types.Run, error) {
	var runs []*types.Run
	err := rs.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		runs, err = rs.d.GetRuns(tx, nil, false, nil, nil, 0, 0, types.SortOrderAsc)
		return errors.WithStack(err)
	})

	return runs, errors.WithStack(err)
}

func compareRuns(r1, r2 []*types.Run) bool {
	r1ids := map[string]struct{}{}
	r2ids := map[string]struct{}{}

	for _, r := range r1 {
		r1ids[r.ID] = struct{}{}
	}
	for _, r := range r2 {
		r2ids[r.ID] = struct{}{}
	}

	return reflect.DeepEqual(r1ids, r2ids)
}

func TestExportImport(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	rs := setupRunservice(ctx, t, log, dir)

	t.Logf("starting rs")
	go func() { _ = rs.Run(ctx) }()

	time.Sleep(1 * time.Second)

	for i := 0; i < 10; i++ {
		if _, err := rs.ah.CreateRun(ctx, &action.RunCreateRequest{Group: "/user/user01", RunConfigTasks: map[string]*types.RunConfigTask{"task01": {}}}); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}

	time.Sleep(5 * time.Second)

	// Do some more changes
	for i := 10; i < 20; i++ {
		if _, err := rs.ah.CreateRun(ctx, &action.RunCreateRequest{Group: "/user/user01", RunConfigTasks: map[string]*types.RunConfigTask{"task01": {}}}); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}

	time.Sleep(5 * time.Second)

	runs, err := getRuns(ctx, rs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(runs) != 20 {
		t.Logf("runs: %s", util.Dump(runs))
		t.Fatalf("expected %d runs, got %d runs", 20, len(runs))
	}

	var export bytes.Buffer
	if err := rs.ah.Export(ctx, &export); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if err := rs.ah.MaintenanceMode(ctx, true); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	time.Sleep(5 * time.Second)

	if err := rs.ah.Import(ctx, &export); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if err := rs.ah.MaintenanceMode(ctx, false); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	time.Sleep(5 * time.Second)

	newRuns, err := getRuns(ctx, rs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if !compareRuns(runs, newRuns) {
		t.Logf("len(runs): %d", len(runs))
		t.Logf("len(newRuns): %d", len(newRuns))
		t.Logf("runs: %s", util.Dump(runs))
		t.Logf("newRuns: %s", util.Dump(newRuns))
		t.Fatalf("runs are different between before and after import")
	}
}

func TestConcurrentRunCreation(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	rs := setupRunservice(ctx, t, log, dir)

	t.Logf("starting rs")
	go func() { _ = rs.Run(ctx) }()

	time.Sleep(1 * time.Second)

	startCh := make(chan struct{})
	var startWg sync.WaitGroup
	var endWg sync.WaitGroup
	for i := 0; i < 10; i++ {
		startWg.Add(1)
		endWg.Add(1)
		go func() {
			startWg.Done()
			<-startCh
			if _, err := rs.ah.CreateRun(ctx, &action.RunCreateRequest{Group: "/user/user01", RunConfigTasks: map[string]*types.RunConfigTask{"task01": {}}}); err != nil {
				t.Errorf("unexpected err: %v", err)
			}
			endWg.Done()
		}()
	}

	startWg.Wait()
	close(startCh)
	endWg.Wait()

	runs, err := getRuns(ctx, rs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(runs) != 10 {
		t.Logf("runs: %s", util.Dump(runs))
		t.Fatalf("expected %d runs, got %d runs", 10, len(runs))
	}

	for i, r := range runs {
		expectedCounter := uint64(i + 1)
		if r.Counter != expectedCounter {
			t.Fatalf("expected run counter %d runs, got %d", expectedCounter, r.Counter)
		}

		expectedSequence := uint64(i + 1)
		if r.Sequence != expectedSequence {
			t.Fatalf("expected run sequence %d runs, got %d", expectedSequence, r.Sequence)
		}
	}
}

func TestGetRunsLastRun(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	rs := setupRunservice(ctx, t, log, dir)

	t.Logf("starting rs")
	go func() { _ = rs.Run(ctx) }()

	time.Sleep(1 * time.Second)

	groups := []string{"/user/user01", "/user/user02"}

	expectedRuns := make([]*types.Run, len(groups))
	for i, group := range groups {
		var lastRun *types.Run
		for i := 0; i < 10; i++ {
			rb, err := rs.ah.CreateRun(ctx, &action.RunCreateRequest{Group: group, RunConfigTasks: map[string]*types.RunConfigTask{"task01": {}}})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			lastRun = rb.Run
		}
		expectedRuns[len(groups)-1-i] = lastRun
	}

	var runs []*types.Run
	err := rs.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		runs, err = rs.d.GetRuns(tx, groups, true, nil, nil, 0, 0, types.SortOrderDesc)

		return errors.WithStack(err)
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if len(runs) != 2 {
		t.Logf("runs: %s", util.Dump(runs))
		t.Fatalf("expected %d runs, got %d runs", 2, len(runs))
	}

	for i, er := range expectedRuns {
		r := runs[i]
		if r.Group != er.Group {
			t.Fatalf("expected run group %q runs, got %q", r.Group, er.Group)
		}

		if r.Sequence != er.Sequence {
			t.Fatalf("expected run sequence %d runs, got %d", er.Sequence, r.Sequence)
		}
	}
}
