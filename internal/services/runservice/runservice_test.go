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
	"io"
	"net"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/runservice/action"
	"agola.io/agola/internal/services/runservice/common"
	"agola.io/agola/internal/services/runservice/store"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/runservice/types"
)

func setupRunservice(ctx context.Context, t *testing.T, log zerolog.Logger, dir string) *Runservice {
	port, err := testutil.GetFreePort("localhost", true, false)
	testutil.NilError(t, err)

	ostDir, err := os.MkdirTemp(dir, "ost")
	testutil.NilError(t, err)

	rsDir, err := os.MkdirTemp(dir, "rs")
	testutil.NilError(t, err)

	dbType := testutil.DBType(t)
	_, _, dbConnString := testutil.CreateDB(t, log, ctx, dir)

	baseConfig := config.Runservice{
		DB: config.DB{
			Type:       dbType,
			ConnString: dbConnString,
		},
		ObjectStorage: config.ObjectStorage{
			Type: config.ObjectStorageTypePosix,
			Path: ostDir,
		},
		Web: config.Web{},
	}
	rsConfig := baseConfig
	rsConfig.DataDir = rsDir
	rsConfig.Web.ListenAddress = net.JoinHostPort("localhost", port)

	rs, err := NewRunservice(ctx, log, &rsConfig)
	testutil.NilError(t, err)

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
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	rs := setupRunservice(ctx, t, log, dir)

	t.Logf("starting rs")
	go func() { _ = rs.Run(ctx) }()

	for i := 0; i < 20; i++ {
		_, err := rs.ah.CreateRun(ctx, &action.RunCreateRequest{Group: "/user/user01", RunConfigTasks: map[string]*types.RunConfigTask{"task01": {}}})
		testutil.NilError(t, err)
	}

	runs, err := getRuns(ctx, rs)
	testutil.NilError(t, err)

	assert.Assert(t, cmp.Len(runs, 20))

	var export bytes.Buffer
	err = rs.ah.Export(ctx, &export)
	testutil.NilError(t, err)

	err = rs.ah.SetMaintenanceEnabled(ctx, true)
	testutil.NilError(t, err)

	_ = testutil.Wait(30*time.Second, func() (bool, error) {
		if !rs.ah.IsMaintenanceMode() {
			return false, nil
		}

		return true, nil
	})
	err = rs.ah.Import(ctx, &export)
	testutil.NilError(t, err)

	err = rs.ah.SetMaintenanceEnabled(ctx, false)
	testutil.NilError(t, err)

	_ = testutil.Wait(30*time.Second, func() (bool, error) {
		if rs.ah.IsMaintenanceMode() {
			return false, nil
		}

		return true, nil
	})

	newRuns, err := getRuns(ctx, rs)
	testutil.NilError(t, err)

	if !compareRuns(runs, newRuns) {
		t.Logf("len(runs): %d", len(runs))
		t.Logf("len(newRuns): %d", len(newRuns))
		t.Logf("runs: %s", util.Dump(runs))
		t.Logf("newRuns: %s", util.Dump(newRuns))
		t.Fatalf("runs are different between before and after import")
	}
}

func TestConcurrentRunCreation(t *testing.T) {
	t.Parallel()

	// TODO(sgotti) Postgres currently (as of v15) returns unique constraint
	// errors hiding serializable errors also if we check for the existance
	// before the insert.
	// If we have a not existing runcounter for groupid and multiple concurrent
	// transactions try to insert the new runcounter only one will succeed and
	// the others will receive a unique constraint violation error instead of a
	// serialization error and won't by retried
	// During an update of an already existing runcounter instead a serialiation
	// error will be returned.
	//
	// This is probably related to this issue with multiple unique indexes
	// https://www.postgresql.org/message-id/flat/CAGPCyEZG76zjv7S31v_xPeLNRuzj-m%3DY2GOY7PEzu7vhB%3DyQog%40mail.gmail.com
	//
	// for now skip this test on posgres
	dbType := testutil.DBType(t)
	if dbType == sql.Postgres {
		t.SkipNow()
	}

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	rs := setupRunservice(ctx, t, log, dir)

	t.Logf("starting rs")
	go func() { _ = rs.Run(ctx) }()

	startCh := make(chan struct{})
	var startWg sync.WaitGroup
	var endWg sync.WaitGroup
	for i := 0; i < 10; i++ {
		startWg.Add(1)
		endWg.Add(1)
		go func() {
			startWg.Done()
			<-startCh
			_, err := rs.ah.CreateRun(ctx, &action.RunCreateRequest{Group: "/user/user01", RunConfigTasks: map[string]*types.RunConfigTask{"task01": {}}})
			testutil.NilError(t, err)

			endWg.Done()
		}()
	}

	startWg.Wait()
	close(startCh)
	endWg.Wait()

	runs, err := getRuns(ctx, rs)
	testutil.NilError(t, err)

	assert.Assert(t, cmp.Len(runs, 10))

	for i, r := range runs {
		expectedCounter := uint64(i + 1)
		assert.Equal(t, r.Counter, expectedCounter)

		expectedSequence := uint64(i + 1)
		assert.Equal(t, r.Sequence, expectedSequence)
	}
}

func TestGetRunsLastRun(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	rs := setupRunservice(ctx, t, log, dir)

	t.Logf("starting rs")
	go func() { _ = rs.Run(ctx) }()

	groups := []string{"/user/user01", "/user/user02"}

	expectedRuns := make([]*types.Run, len(groups))
	for i, group := range groups {
		var lastRun *types.Run
		for i := 0; i < 10; i++ {
			rb, err := rs.ah.CreateRun(ctx, &action.RunCreateRequest{Group: group, RunConfigTasks: map[string]*types.RunConfigTask{"task01": {}}})
			testutil.NilError(t, err)

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
	testutil.NilError(t, err)

	assert.Assert(t, cmp.Len(runs, 2))

	for i, er := range expectedRuns {
		r := runs[i]
		assert.Equal(t, r.Group, er.Group)

		assert.Equal(t, r.Sequence, er.Sequence)
	}
}

func TestLogleaner(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	rs := setupRunservice(ctx, t, log, dir)
	rs.c.RunCacheExpireInterval = 604800000000000

	body := io.NopCloser(bytes.NewBufferString("log test"))
	logPath := store.OSTRunTaskStepLogPath("task01", 0)

	err := rs.ost.WriteObject(logPath, body, -1, false)
	testutil.NilError(t, err)

	_, err = rs.ost.ReadObject(logPath)
	testutil.NilError(t, err)

	time.Sleep(1 * time.Second)

	err = rs.objectsCleaner(ctx, store.OSTLogsBaseDir(), common.LogCleanerLockKey, 1*time.Millisecond)
	testutil.NilError(t, err)

	_, err = rs.ost.ReadObject(logPath)
	assert.ErrorType(t, err, objectstorage.IsNotExist)
}
