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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"agola.io/agola/internal/objectstorage"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/runservice/action"
	"agola.io/agola/internal/services/runservice/common"
	"agola.io/agola/internal/services/runservice/store"
	"agola.io/agola/internal/sqlg"
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
		runs, err = rs.d.GetRuns(tx, nil, false, nil, nil, 0, 0, types.SortDirectionAsc)
		return errors.WithStack(err)
	})

	return runs, errors.WithStack(err)
}

func compareRunsIDs(r1, r2 []*types.Run) bool {
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

func cmpDiffObject(x, y interface{}) cmp.Comparison {
	// Since postgres has microsecond time precision while go has nanosecond time precision we should check times with a microsecond margin
	return cmp.DeepEqual(x, y, cmpopts.IgnoreFields(sqlg.ObjectMeta{}, "TxID"), cmpopts.EquateApproxTime(1*time.Microsecond))
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

	err = testutil.Wait(30*time.Second, func() (bool, error) {
		if !rs.ah.IsMaintenanceMode() {
			return false, nil
		}

		return true, nil
	})
	testutil.NilError(t, err)

	err = rs.ah.Import(ctx, &export)
	testutil.NilError(t, err)

	err = rs.ah.SetMaintenanceEnabled(ctx, false)
	testutil.NilError(t, err)

	err = testutil.Wait(30*time.Second, func() (bool, error) {
		if rs.ah.IsMaintenanceMode() {
			return false, nil
		}

		return true, nil
	})
	testutil.NilError(t, err)

	newRuns, err := getRuns(ctx, rs)
	testutil.NilError(t, err)

	if !compareRunsIDs(runs, newRuns) {
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
		runs, err = rs.d.GetRuns(tx, groups, true, nil, nil, 0, 0, types.SortDirectionDesc)

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

	err := rs.ost.WriteObject(ctx, logPath, body, -1, false)
	testutil.NilError(t, err)

	_, err = rs.ost.ReadObject(ctx, logPath)
	testutil.NilError(t, err)

	time.Sleep(1 * time.Second)

	err = rs.objectsCleaner(ctx, store.OSTLogsBaseDir(), common.LogCleanerLockKey, 1*time.Millisecond)
	testutil.NilError(t, err)

	_, err = rs.ost.ReadObject(ctx, logPath)
	assert.ErrorType(t, err, objectstorage.IsNotExist)
}

func TestGetGroupRuns(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	rs := setupRunservice(ctx, t, log, dir)

	group01All := "/user/user01"
	group01Branch01 := "/user/user01/branch01"
	group01Pr01 := "/user/user01/pr01"

	runCount := 10
	for i := 0; i < runCount; i++ {
		c := i % 2
		group := group01Branch01
		if c == 1 {
			group = group01Pr01
		}

		_, err := rs.ah.CreateRun(ctx, &action.RunCreateRequest{Group: group, RunConfigTasks: map[string]*types.RunConfigTask{"task01": {}}})
		testutil.NilError(t, err)
	}

	var runs []*types.Run
	err := rs.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		runs, err = rs.d.GetRuns(tx, []string{group01All}, false, nil, nil, 0, 0, types.SortDirectionAsc)

		return errors.WithStack(err)
	})
	testutil.NilError(t, err)

	for i, run := range runs {
		c := i % 3

		if c == 0 {
			continue
		}

		err := rs.d.Do(ctx, func(tx *sql.Tx) error {
			var err error
			run, err := rs.d.GetRun(tx, run.ID)
			if err != nil {
				return errors.WithStack(err)
			}

			// mark some runs as finished/success
			if c == 1 {
				run.Phase = types.RunPhaseFinished
				run.Result = types.RunResultSuccess
			}
			// mark some runs as finished/failed
			if c == 2 {
				run.Phase = types.RunPhaseFinished
				run.Result = types.RunResultFailed
			}
			if err := rs.d.UpdateRun(tx, run); err != nil {
				return errors.WithStack(err)
			}

			return nil
		})
		testutil.NilError(t, err)
	}

	err = rs.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		runs, err = rs.d.GetRuns(tx, []string{group01All}, false, nil, nil, 0, 0, types.SortDirectionAsc)

		return errors.WithStack(err)
	})
	testutil.NilError(t, err)

	tests := []struct {
		name                string
		limit               int
		sortDirection       types.SortDirection
		group               string
		startRunCounter     uint64
		phaseFilter         []types.RunPhase
		resultFilter        []types.RunResult
		expectedRunsNumber  int
		expectedCallsNumber int
	}{
		{
			name:                "get runs with limit = 0, no sortdirection",
			group:               group01All,
			expectedRunsNumber:  10,
			expectedCallsNumber: 1,
		},
		{
			name:                "get runs with limit = 0",
			group:               group01All,
			sortDirection:       types.SortDirectionAsc,
			expectedRunsNumber:  10,
			expectedCallsNumber: 1,
		},
		{
			name:                "get runs with limit less than runs",
			group:               group01All,
			limit:               2,
			sortDirection:       types.SortDirectionAsc,
			expectedRunsNumber:  10,
			expectedCallsNumber: 5,
		},
		{
			name:                "get runs with limit greater than runs",
			group:               group01All,
			limit:               10,
			sortDirection:       types.SortDirectionAsc,
			expectedRunsNumber:  10,
			expectedCallsNumber: 1,
		},
		{
			name:                "get runs with limit = 0, startCounter = 3",
			group:               group01All,
			sortDirection:       types.SortDirectionAsc,
			startRunCounter:     3,
			expectedRunsNumber:  7,
			expectedCallsNumber: 1,
		},
		{
			name:                "get runs with limit less than runs, startCounter = 3",
			group:               group01All,
			limit:               2,
			sortDirection:       types.SortDirectionAsc,
			startRunCounter:     3,
			expectedRunsNumber:  7,
			expectedCallsNumber: 4,
		},
		{
			name:                "get runs with limit less than runs, phaseFilter finished",
			group:               group01All,
			limit:               2,
			sortDirection:       types.SortDirectionAsc,
			phaseFilter:         []types.RunPhase{types.RunPhaseFinished},
			expectedRunsNumber:  6,
			expectedCallsNumber: 3,
		},
		{
			name:                "get runs with limit less than runs, resultFilter failed",
			group:               group01All,
			limit:               2,
			sortDirection:       types.SortDirectionAsc,
			resultFilter:        []types.RunResult{types.RunResultFailed},
			expectedRunsNumber:  3,
			expectedCallsNumber: 2,
		},
		{
			name:                "get runs with limit less than runs, phaseFilter finished, resultFilter failed",
			group:               group01All,
			limit:               2,
			sortDirection:       types.SortDirectionAsc,
			phaseFilter:         []types.RunPhase{types.RunPhaseFinished},
			resultFilter:        []types.RunResult{types.RunResultFailed},
			expectedRunsNumber:  3,
			expectedCallsNumber: 2,
		},
		{
			name:                "get runs with limit less than runs, phaseFilter finished, resultFilter success or failed",
			group:               group01All,
			limit:               2,
			sortDirection:       types.SortDirectionAsc,
			phaseFilter:         []types.RunPhase{types.RunPhaseFinished},
			resultFilter:        []types.RunResult{types.RunResultSuccess, types.RunResultFailed},
			expectedRunsNumber:  6,
			expectedCallsNumber: 3,
		},
		{
			name:                "get runs with limit = 0, sortDirection desc",
			group:               group01All,
			sortDirection:       types.SortDirectionDesc,
			expectedRunsNumber:  10,
			expectedCallsNumber: 1,
		},
		{
			name:                "get runs with limit less than runs, sortDirection desc",
			group:               group01All,
			limit:               2,
			sortDirection:       types.SortDirectionDesc,
			expectedRunsNumber:  10,
			expectedCallsNumber: 5,
		},
		{
			name:                "get runs with limit greater than runs, sortDirection desc",
			group:               group01All,
			limit:               10,
			sortDirection:       types.SortDirectionDesc,
			expectedRunsNumber:  10,
			expectedCallsNumber: 1,
		},
		{
			name:                "get runs with limit = 0, startCounter = 3, sortDirection desc",
			group:               group01All,
			sortDirection:       types.SortDirectionDesc,
			startRunCounter:     3,
			expectedRunsNumber:  2,
			expectedCallsNumber: 1,
		},
		{
			name:                "get runs with limit less than runs, startCounter = 3, sortDirection desc",
			group:               group01All,
			limit:               2,
			sortDirection:       types.SortDirectionDesc,
			startRunCounter:     3,
			expectedRunsNumber:  2,
			expectedCallsNumber: 1,
		},
		{
			name:                "get runs with limit less than runs, phaseFilter finished, sortDirection desc",
			group:               group01All,
			limit:               2,
			sortDirection:       types.SortDirectionDesc,
			phaseFilter:         []types.RunPhase{types.RunPhaseFinished},
			expectedRunsNumber:  6,
			expectedCallsNumber: 3,
		},
		{
			name:                "get runs with limit less than runs, resultFilter failed, sortDirection desc",
			group:               group01All,
			limit:               2,
			sortDirection:       types.SortDirectionDesc,
			resultFilter:        []types.RunResult{types.RunResultFailed},
			expectedRunsNumber:  3,
			expectedCallsNumber: 2,
		},
		{
			name:                "get runs with limit less than runs, phaseFilter finished, resultFilter failed, sortDirection desc",
			group:               group01All,
			limit:               2,
			sortDirection:       types.SortDirectionDesc,
			phaseFilter:         []types.RunPhase{types.RunPhaseFinished},
			resultFilter:        []types.RunResult{types.RunResultFailed},
			expectedRunsNumber:  3,
			expectedCallsNumber: 2,
		},
		{
			name:                "get runs with limit less than runs, phaseFilter finished, resultFilter success or failed, sortDirection desc",
			group:               group01All,
			limit:               2,
			sortDirection:       types.SortDirectionDesc,
			phaseFilter:         []types.RunPhase{types.RunPhaseFinished},
			resultFilter:        []types.RunResult{types.RunResultSuccess, types.RunResultFailed},
			expectedRunsNumber:  6,
			expectedCallsNumber: 3,
		},
		{
			name:                "get runs with group /user/user01/branch01, limit less than runs",
			group:               group01Branch01,
			limit:               2,
			sortDirection:       types.SortDirectionAsc,
			expectedRunsNumber:  5,
			expectedCallsNumber: 3,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// default sortdirection is desc

			curRuns := append([]*types.Run{}, runs...)
			expectedRuns := []*types.Run{}
			for _, run := range curRuns {
				if tt.startRunCounter > 0 {
					if tt.sortDirection == types.SortDirectionDesc || tt.sortDirection == "" {
						// keep only runs with runCounter < startRunCounter
						if run.Counter >= tt.startRunCounter {
							continue
						}
					} else {
						// keep only runs with runCounter > startRunCounter
						if run.Counter <= tt.startRunCounter {
							continue
						}
					}
				}

				group := tt.group
				runGroup := run.Group
				if !strings.HasSuffix(group, "/") {
					group += "/"
				}
				if !strings.HasSuffix(runGroup, "/") {
					runGroup += "/"
				}
				if !strings.HasPrefix(runGroup, group) {
					continue
				}

				if len(tt.phaseFilter) > 0 && !slices.Contains(tt.phaseFilter, run.Phase) {
					continue
				}
				if len(tt.resultFilter) > 0 && !slices.Contains(tt.resultFilter, run.Result) {
					continue
				}
				expectedRuns = append(expectedRuns, run)
			}

			// reverse if sortDirection is desc
			if tt.sortDirection == types.SortDirectionDesc || tt.sortDirection == "" {
				slices.Reverse(expectedRuns)
			}

			callsNumber := 0
			var respAllRuns []*types.Run
			startRunCounter := tt.startRunCounter

			for {
				res, err := rs.ah.GetGroupRuns(ctx, &action.GetGroupRunsRequest{Group: tt.group, StartRunCounter: startRunCounter, Limit: tt.limit, SortDirection: tt.sortDirection, PhaseFilter: tt.phaseFilter, ResultFilter: tt.resultFilter})
				testutil.NilError(t, err)

				callsNumber++

				respAllRuns = append(respAllRuns, res.Runs...)

				if !res.HasMore {
					break
				}

				lastRun := res.Runs[len(res.Runs)-1]
				startRunCounter = lastRun.Counter
			}

			assert.Assert(t, cmp.Len(respAllRuns, tt.expectedRunsNumber))
			assert.Assert(t, cmpDiffObject(expectedRuns, respAllRuns))
			assert.Equal(t, callsNumber, tt.expectedCallsNumber)
		})
	}
}
