// Copyright 2023 Sorint.lab
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

package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/notification/action"
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/notification/types"
	rsclient "agola.io/agola/services/runservice/client"
	rstypes "agola.io/agola/services/runservice/types"
)

const (
	webhookSecret          = "secretkey"
	webhookPayload         = "payloadtest"
	webhookURL             = "testWebhookURL"
	project01              = "project01id"
	project02              = "project02id"
	runWebhookDelivery01   = "runwebhookdelivery01id"
	commitStatusDelivery01 = "commitstatusdelivery01id"
)

// setupNotificationService don't start the notification service but just create it to manually call its methods
func setupNotificationService(ctx context.Context, t *testing.T, log zerolog.Logger, dir string) *NotificationService {
	dbType := testutil.DBType(t)
	_, _, dbConnString := testutil.CreateDB(t, log, ctx, dir)

	c := config.Config{
		Notification: config.Notification{
			DB: config.DB{
				Type:       dbType,
				ConnString: dbConnString,
			},
		},
	}

	ns, err := NewNotificationService(ctx, log, &c)
	testutil.NilError(t, err)

	return ns
}

func TestRunWebhookDelivery(t *testing.T) {
	t.Parallel()

	t.Run("test run webhook delivery success", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		wr := setupWebhooksReceiver(ctx, t)
		defer wr.stop()

		t.Logf("starting webhooks client")

		ns.c.WebhookURL = fmt.Sprintf("%s/%s", wr.exposedURL, "webhooks")
		ns.c.WebhookSecret = webhookSecret

		runWebhooks := make([]*types.RunWebhook, MaxRunWebhookDeliveriesQueryLimit+10)
		for i := 0; i < len(runWebhooks); i++ {
			runWebhooks[i] = createRunWebhook(t, ctx, ns, project01)
			createRunWebhookDelivery(t, ctx, ns, runWebhooks[i].ID, types.DeliveryStatusNotDelivered)
		}
		err := ns.runWebhookDeliveriesHandler(ctx)
		testutil.NilError(t, err)

		runWebhookDeliveries := getRunWebhookDeliveries(t, ctx, ns)
		assert.Assert(t, cmp.Len(runWebhookDeliveries, len(runWebhooks)))
		for i := 0; i < len(runWebhookDeliveries); i++ {
			assert.Equal(t, runWebhookDeliveries[i].DeliveryStatus, types.DeliveryStatusDelivered)
		}

		webhooks, err := wr.webhooks.getWebhooks()
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(webhooks, len(runWebhooks)))
		for i := 0; i < len(runWebhookDeliveries); i++ {
			assert.Assert(t, bytes.Equal(webhooks[i].Payload, runWebhooks[i].Payload))

			h256 := hmac.New(sha256.New, []byte(webhookSecret))
			_, err = h256.Write([]byte(runWebhooks[i].Payload))
			testutil.NilError(t, err)

			expectedsignature := hex.EncodeToString(h256.Sum(nil))

			assert.Equal(t, webhooks[i].Signature, expectedsignature)
		}

		// test run webhooks handled previously.

		wr.webhooks.resetWebhooks()

		err = ns.runWebhookDeliveriesHandler(ctx)
		testutil.NilError(t, err)

		webhooks, err = wr.webhooks.getWebhooks()
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(webhooks, 0))
	})

	t.Run("test run webhook delivery fail", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		runWebhook := createRunWebhook(t, ctx, ns, project01)
		createRunWebhookDelivery(t, ctx, ns, runWebhook.ID, types.DeliveryStatusNotDelivered)
		err := ns.runWebhookDeliveriesHandler(ctx)
		testutil.NilError(t, err)

		runWebhookDeliveries := getRunWebhookDeliveries(t, ctx, ns)
		assert.Assert(t, cmp.Len(runWebhookDeliveries, 1))
		assert.Equal(t, runWebhookDeliveries[0].DeliveryStatus, types.DeliveryStatusDeliveryError)
	})
}

func TestLastRunEventSequence(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	log := testutil.NewLogger(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ns := setupNotificationService(ctx, t, log, dir)
	ns.c.WebhookURL = webhookURL

	runEventsSender := setupRunEventsSender(ctx, t)
	defer runEventsSender.stop()

	t.Logf("starting run events service")

	ns.runserviceClient = rsclient.NewClient(runEventsSender.exposedURL, "")

	lastRunEventSequenceValue := getLastRunEventSequenceValue(t, ctx, ns)
	assert.Equal(t, lastRunEventSequenceValue, uint64(0))

	// test runEventsHandler start from sequence 0
	runEvents := make([]*rstypes.RunEvent, 0)
	runEvents = append(runEvents, generateRunEvent(1, rstypes.RunPhaseChanged))
	runEvents = append(runEvents, generateRunEvent(2, rstypes.RunPhaseChanged))

	runEventsSender.runEvents.addRunEvent(runEvents[0])
	runEventsSender.runEvents.addRunEvent(runEvents[1])
	expectedLastRunEventSequenceValue := uint64(2)

	err := ns.runEventsHandler(ctx)
	testutil.NilError(t, err)

	lastRunEventSequenceValue = getLastRunEventSequenceValue(t, ctx, ns)
	assert.Equal(t, lastRunEventSequenceValue, expectedLastRunEventSequenceValue)

	// test new events
	runEvents = append(runEvents, generateRunEvent(3, rstypes.RunPhaseChanged))
	runEvents = append(runEvents, generateRunEvent(4, rstypes.RunPhaseChanged))

	runEventsSender.runEvents.addRunEvent(runEvents[2])
	runEventsSender.runEvents.addRunEvent(runEvents[3])

	err = ns.runEventsHandler(ctx)
	testutil.NilError(t, err)

	runWebhooks := getRunWebhooks(t, ctx, ns)
	assert.Assert(t, cmp.Len(runWebhooks, len(runEvents)))

	for i := range runEvents {
		runWebhook := ns.generatewebhook(ctx, runEvents[i])
		webhookPayload, err := json.Marshal(runWebhook)
		testutil.NilError(t, err)

		assert.Assert(t, bytes.Equal(runWebhooks[i].Payload, webhookPayload))
	}

	expectedLastRunEventSequenceValue = 4
	lastRunEventSequenceValue = getLastRunEventSequenceValue(t, ctx, ns)
	assert.Equal(t, lastRunEventSequenceValue, expectedLastRunEventSequenceValue)
}

func generateRunEvent(sequence uint64, runEventType rstypes.RunEventType) *rstypes.RunEvent {
	return &rstypes.RunEvent{
		Sequence:     sequence,
		RunEventType: runEventType,
		DataVersion:  rstypes.RunEventDataVersion,
		Data:         &rstypes.RunEventData{},
	}
}

func getLastRunEventSequenceValue(t *testing.T, ctx context.Context, ns *NotificationService) uint64 {
	var lastRunEventSequence uint64

	err := ns.d.Do(ctx, func(tx *sql.Tx) error {
		l, err := ns.d.GetLastRunEventSequence(tx)
		if err != nil {
			return errors.WithStack(err)
		}
		if l != nil {
			lastRunEventSequence = l.Value
		}

		return nil
	})
	testutil.NilError(t, err)

	return lastRunEventSequence
}

func getRunWebhookDeliveries(t *testing.T, ctx context.Context, ns *NotificationService) []*types.RunWebhookDelivery {
	var wd []*types.RunWebhookDelivery

	err := ns.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		wd, err = ns.d.GetRunWebhookDeliveriesAfterSequence(tx, 0, 0)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	testutil.NilError(t, err)

	return wd
}

func createRunWebhook(t *testing.T, ctx context.Context, ns *NotificationService, projectID string) *types.RunWebhook {
	var wh *types.RunWebhook

	err := ns.d.Do(ctx, func(tx *sql.Tx) error {
		wh = types.NewRunWebhook(tx)
		wh.Payload = []byte(webhookPayload)
		wh.ProjectID = projectID

		if err := ns.d.InsertRunWebhook(tx, wh); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	testutil.NilError(t, err)

	return wh
}

func getRunWebhooks(t *testing.T, ctx context.Context, ns *NotificationService) []*types.RunWebhook {
	var runWebhooks []*types.RunWebhook

	err := ns.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		runWebhooks, err = ns.d.GetRunWebhooks(tx, 0)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	testutil.NilError(t, err)

	return runWebhooks
}

func createRunWebhookDelivery(t *testing.T, ctx context.Context, ns *NotificationService, runWebhookID string, deliveryStatus types.DeliveryStatus) *types.RunWebhookDelivery {
	var wd *types.RunWebhookDelivery

	err := ns.d.Do(ctx, func(tx *sql.Tx) error {
		wd = types.NewRunWebhookDelivery(tx)
		wd.DeliveryStatus = deliveryStatus
		wd.RunWebhookID = runWebhookID

		if err := ns.d.InsertRunWebhookDelivery(tx, wd); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	testutil.NilError(t, err)

	return wd
}

func updateRunWebhookCreationDate(t *testing.T, ctx context.Context, ns *NotificationService, runWebhookID string, creationTime time.Time) {
	err := ns.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		runWebhook, err := ns.d.GetRunWebhookByID(tx, runWebhookID)
		if err != nil {
			return errors.WithStack(err)
		}

		runWebhook.CreationTime = creationTime
		if err := ns.d.UpdateRunWebhook(tx, runWebhook); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	testutil.NilError(t, err)
}

func TestCommitStatusDelivery(t *testing.T) {
	t.Parallel()

	t.Run("test commit status delivery success", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		cs := setupStubCommitStatusUpdater()
		ns.u = cs

		commitStatuses := make([]*types.CommitStatus, MaxCommitStatusDeliveriesQueryLimit+10)
		for i := 0; i < len(commitStatuses); i++ {
			commitStatuses[i] = createCommitStatus(t, ctx, ns, i, fmt.Sprintf("projectID-%d", i))
			createCommitStatusDelivery(t, ctx, ns, commitStatuses[i].ID, types.DeliveryStatusNotDelivered)
		}
		err := ns.commitStatusDeliveriesHandler(ctx)
		testutil.NilError(t, err)

		commitStatusDeliveries := getCommitStatusDeliveries(t, ctx, ns)
		assert.Assert(t, cmp.Len(commitStatusDeliveries, len(commitStatuses)))
		for i := 0; i < len(commitStatusDeliveries); i++ {
			assert.Equal(t, commitStatusDeliveries[i].DeliveryStatus, types.DeliveryStatusDelivered)
		}

		commitStatusesReceived, err := cs.commitStatuses.getCommitStatuses()
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(commitStatusesReceived, len(commitStatuses)))
		for i := 0; i < len(commitStatuses); i++ {
			assert.Equal(t, commitStatusesReceived[i].Context, commitStatuses[i].Context)
			assert.Equal(t, commitStatusesReceived[i].Description, commitStatuses[i].Description)
			assert.Equal(t, commitStatusesReceived[i].State, commitStatuses[i].State)
		}

		// test commitstatuses handled previously.

		cs.commitStatuses.resetCommitStatuses()

		err = ns.commitStatusDeliveriesHandler(ctx)
		testutil.NilError(t, err)

		commitStatusesReceived, err = cs.commitStatuses.getCommitStatuses()
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(commitStatusesReceived, 0))
	})

	t.Run("test commit status delivery fail", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		s := setupStubCommitStatusUpdater()
		s.setFailUpdateCommitStatus(true)
		ns.u = s

		commitStatus := createCommitStatus(t, ctx, ns, 1, project01)
		createCommitStatusDelivery(t, ctx, ns, commitStatus.ID, types.DeliveryStatusNotDelivered)
		err := ns.commitStatusDeliveriesHandler(ctx)
		testutil.NilError(t, err)

		commitStatusDeliveries := getCommitStatusDeliveries(t, ctx, ns)
		assert.Assert(t, cmp.Len(commitStatusDeliveries, 1))
		assert.Equal(t, commitStatusDeliveries[0].DeliveryStatus, types.DeliveryStatusDeliveryError)
	})
}

func createCommitStatus(t *testing.T, ctx context.Context, ns *NotificationService, runCounter int, projectID string) *types.CommitStatus {
	var cs *types.CommitStatus

	err := ns.d.Do(ctx, func(tx *sql.Tx) error {
		cs = types.NewCommitStatus(tx)
		// CommitSHAuse and Context use dumb values
		cs.CommitSHA = fmt.Sprintf("commitSHA-%d", runCounter)
		cs.Context = fmt.Sprintf("context-%d", runCounter)
		cs.Description = "The run finished successfully"
		cs.ProjectID = projectID
		cs.RunCounter = uint64(runCounter)
		cs.State = types.CommitStateSuccess

		if err := ns.d.InsertCommitStatus(tx, cs); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	testutil.NilError(t, err)

	return cs
}

func updateCommitStatusCreationDate(t *testing.T, ctx context.Context, ns *NotificationService, commitStatusID string, creationTime time.Time) {
	err := ns.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		commitStatus, err := ns.d.GetCommitStatusByID(tx, commitStatusID)
		if err != nil {
			return errors.WithStack(err)
		}

		commitStatus.CreationTime = creationTime
		if err := ns.d.UpdateCommitStatus(tx, commitStatus); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	testutil.NilError(t, err)
}

func getCommitStatuses(t *testing.T, ctx context.Context, ns *NotificationService) []*types.CommitStatus {
	var commitStatuses []*types.CommitStatus

	err := ns.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		commitStatuses, err = ns.d.GetCommitStatuses(tx, 0)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	testutil.NilError(t, err)

	return commitStatuses
}

func getCommitStatusDeliveries(t *testing.T, ctx context.Context, ns *NotificationService) []*types.CommitStatusDelivery {
	var wd []*types.CommitStatusDelivery

	err := ns.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		wd, err = ns.d.GetCommitStatusDeliveriesAfterSequence(tx, 0, 0)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	testutil.NilError(t, err)

	return wd
}

func createCommitStatusDelivery(t *testing.T, ctx context.Context, ns *NotificationService, commitStatusID string, deliveryStatus types.DeliveryStatus) *types.CommitStatusDelivery {
	var delivery *types.CommitStatusDelivery

	err := ns.d.Do(ctx, func(tx *sql.Tx) error {
		delivery = types.NewCommitStatusDelivery(tx)
		delivery.DeliveryStatus = deliveryStatus
		delivery.CommitStatusID = commitStatusID

		if err := ns.d.InsertCommitStatusDelivery(tx, delivery); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	testutil.NilError(t, err)

	return delivery
}

func TestGetProjectRunWebhookDeliveries(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	log := testutil.NewLogger(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ns := setupNotificationService(ctx, t, log, dir)

	runWebhooks := make([]*types.RunWebhook, 10)
	project01RunWebhookDeliveries := make([]*types.RunWebhookDelivery, 0)
	for i := 0; i < len(runWebhooks); i++ {
		runWebhooks[i] = createRunWebhook(t, ctx, ns, project01)
		project01RunWebhookDeliveries = append(project01RunWebhookDeliveries, createRunWebhookDelivery(t, ctx, ns, runWebhooks[i].ID, types.DeliveryStatusDelivered))
		project01RunWebhookDeliveries = append(project01RunWebhookDeliveries, createRunWebhookDelivery(t, ctx, ns, runWebhooks[i].ID, types.DeliveryStatusNotDelivered))
	}

	for i := 0; i < len(runWebhooks); i++ {
		runWebhooks[i] = createRunWebhook(t, ctx, ns, project02)
		createRunWebhookDelivery(t, ctx, ns, runWebhooks[i].ID, types.DeliveryStatusDelivered)
		createRunWebhookDelivery(t, ctx, ns, runWebhooks[i].ID, types.DeliveryStatusNotDelivered)
	}

	tests := []struct {
		name                               string
		limit                              int
		sortDirection                      types.SortDirection
		deliveryStatusFilter               []types.DeliveryStatus
		expectedRunWebhookDeliveriesNumber int
		expectedCallsNumber                int
	}{
		{
			name:                               "test get run webhook deliveries with limit = 0 and no sortdirection",
			expectedRunWebhookDeliveriesNumber: 20,
			expectedCallsNumber:                1,
		},
		{
			name:                               "test get run webhook deliveries with limit = 0",
			sortDirection:                      types.SortDirectionAsc,
			expectedRunWebhookDeliveriesNumber: 20,
			expectedCallsNumber:                1,
		},
		{
			name:                               "test get run webhook deliveries with deliverystatusfilter = delivered",
			sortDirection:                      types.SortDirectionAsc,
			deliveryStatusFilter:               []types.DeliveryStatus{types.DeliveryStatusDelivered},
			expectedRunWebhookDeliveriesNumber: 10,
			expectedCallsNumber:                1,
		},
		{
			name:                               "test get run webhook deliveries with deliverystatusfilter = delivered and limit less than run webhook deliveries",
			limit:                              2,
			sortDirection:                      types.SortDirectionAsc,
			deliveryStatusFilter:               []types.DeliveryStatus{types.DeliveryStatusDelivered},
			expectedRunWebhookDeliveriesNumber: 10,
			expectedCallsNumber:                5,
		},
		{
			name:                               "test get run webhook deliveries with limit less than run webhook deliveries",
			sortDirection:                      types.SortDirectionAsc,
			limit:                              5,
			expectedRunWebhookDeliveriesNumber: 20,
			expectedCallsNumber:                4,
		},
		{
			name:                               "test get run webhook deliveries with limit = 0 and sortDirection desc",
			sortDirection:                      types.SortDirectionDesc,
			expectedRunWebhookDeliveriesNumber: 20,
			expectedCallsNumber:                1,
		},
		{
			name:                               "test get run webhook deliveries with deliverystatusfilter = delivered and sortDirection desc",
			sortDirection:                      types.SortDirectionDesc,
			deliveryStatusFilter:               []types.DeliveryStatus{types.DeliveryStatusDelivered},
			expectedRunWebhookDeliveriesNumber: 10,
			expectedCallsNumber:                1,
		},
		{
			name:                               "test get run webhook deliveries with deliverystatusfilter = delivered and limit less than run webhook deliveries and sortDirection desc",
			limit:                              2,
			sortDirection:                      types.SortDirectionDesc,
			deliveryStatusFilter:               []types.DeliveryStatus{types.DeliveryStatusDelivered},
			expectedRunWebhookDeliveriesNumber: 10,
			expectedCallsNumber:                5,
		},
		{
			name:                               "test get run webhook deliveries with limit less than run webhook deliveries and sortDirection desc",
			sortDirection:                      types.SortDirectionDesc,
			limit:                              5,
			expectedRunWebhookDeliveriesNumber: 20,
			expectedCallsNumber:                4,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// populate the expected run webhook deliveries
			expectedProject01RunWebhookDeliveries := []*types.RunWebhookDelivery{}
			for _, c := range project01RunWebhookDeliveries {
				if len(tt.deliveryStatusFilter) > 0 && !deliveryStatusInSlice(tt.deliveryStatusFilter, c.DeliveryStatus) {
					continue
				}
				expectedProject01RunWebhookDeliveries = append(expectedProject01RunWebhookDeliveries, c)
			}
			// default sortdirection is asc

			// reverse if sortDirection is desc
			// TODO(sgotti) use go 1.21 generics slices.Reverse when removing support for go < 1.21
			if tt.sortDirection == types.SortDirectionDesc {
				for i, j := 0, len(expectedProject01RunWebhookDeliveries)-1; i < j; i, j = i+1, j-1 {
					expectedProject01RunWebhookDeliveries[i], expectedProject01RunWebhookDeliveries[j] = expectedProject01RunWebhookDeliveries[j], expectedProject01RunWebhookDeliveries[i]
				}
			}

			callsNumber := 0
			var lastProjectRunWebhookDelivery uint64
			var respAllProjectRunWebhookDeliveries []*types.RunWebhookDelivery

			// fetch next results
			for {
				res, err := ns.ah.GetProjectRunWebhookDeliveries(ctx, &action.GetProjectRunWebhookDeliveriesRequest{
					ProjectID:            project01,
					Limit:                tt.limit,
					SortDirection:        tt.sortDirection,
					DeliveryStatusFilter: tt.deliveryStatusFilter,
					StartSequence:        lastProjectRunWebhookDelivery,
				})
				testutil.NilError(t, err)

				callsNumber++

				respAllProjectRunWebhookDeliveries = append(respAllProjectRunWebhookDeliveries, res.RunWebhookDeliveries...)

				if res.HasMore == false {
					break
				}

				lastProjectRunWebhookDelivery = respAllProjectRunWebhookDeliveries[len(respAllProjectRunWebhookDeliveries)-1].Sequence
			}

			assert.Assert(t, cmpDiffObject(expectedProject01RunWebhookDeliveries, respAllProjectRunWebhookDeliveries))
			assert.Assert(t, cmp.Equal(callsNumber, tt.expectedCallsNumber))
		})
	}
}

func TestDeliveryStatusFromStringSlice(t *testing.T) {
	t.Parallel()

	deliverystatus := []string{"notDelivered", "delivered", "deliveryError"}
	expectedDeliveryStatus := []types.DeliveryStatus{
		types.DeliveryStatusNotDelivered,
		types.DeliveryStatusDelivered,
		types.DeliveryStatusDeliveryError,
	}

	result, err := types.DeliveryStatusFromStringSlice(deliverystatus)
	testutil.NilError(t, err)

	assert.DeepEqual(t, result, expectedDeliveryStatus)

	// test wrong deliverystatus
	baddeliverystatus := "baddeliverystatus"
	deliverystatus = []string{string(types.DeliveryStatusNotDelivered), string(types.DeliveryStatusDelivered), string(types.DeliveryStatusDeliveryError), baddeliverystatus}
	_, err = types.DeliveryStatusFromStringSlice(deliverystatus)
	expectedErr := fmt.Sprintf("invalid delivery status %q", baddeliverystatus)
	assert.Error(t, err, expectedErr)
}

func TestRunWebhooksCleaner(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	log := testutil.NewLogger(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ns := setupNotificationService(ctx, t, log, dir)

	expectedRunWebhooks := make([]*types.RunWebhook, 0)
	expectedRunWebhookDeliveries := make([]*types.RunWebhookDelivery, 0)

	for i := 0; i < 5; i++ {
		runWebhook := createRunWebhook(t, ctx, ns, project01)
		expectedRunWebhooks = append(expectedRunWebhooks, runWebhook)

		expectedRunWebhookDeliveries = append(expectedRunWebhookDeliveries, createRunWebhookDelivery(t, ctx, ns, runWebhook.ID, types.DeliveryStatusDelivered))
		expectedRunWebhookDeliveries = append(expectedRunWebhookDeliveries, createRunWebhookDelivery(t, ctx, ns, runWebhook.ID, types.DeliveryStatusNotDelivered))
	}

	for i := 0; i < 5; i++ {
		runWebhook := createRunWebhook(t, ctx, ns, project02)
		expectedRunWebhooks = append(expectedRunWebhooks, runWebhook)

		expectedRunWebhookDeliveries = append(expectedRunWebhookDeliveries, createRunWebhookDelivery(t, ctx, ns, runWebhook.ID, types.DeliveryStatusDelivered))
		expectedRunWebhookDeliveries = append(expectedRunWebhookDeliveries, createRunWebhookDelivery(t, ctx, ns, runWebhook.ID, types.DeliveryStatusNotDelivered))
	}

	runWebhookCreationTime := time.Now().Add(-1 * time.Hour)
	for i := 0; i < 50; i++ {
		runWebhook := createRunWebhook(t, ctx, ns, project01)
		createRunWebhookDelivery(t, ctx, ns, runWebhook.ID, types.DeliveryStatusDelivered)
		createRunWebhookDelivery(t, ctx, ns, runWebhook.ID, types.DeliveryStatusNotDelivered)

		updateRunWebhookCreationDate(t, ctx, ns, runWebhook.ID, runWebhookCreationTime)
	}

	err := ns.runWebhooksCleaner(ctx, 30*time.Minute)
	testutil.NilError(t, err)

	runWebhooks := getRunWebhooks(t, ctx, ns)
	assert.Assert(t, cmp.Len(runWebhooks, len(expectedRunWebhooks)))
	assert.Assert(t, cmpDiffObject(runWebhooks, expectedRunWebhooks))

	runWebhookDeliveries := getRunWebhookDeliveries(t, ctx, ns)
	testutil.NilError(t, err)

	assert.Assert(t, cmp.Len(runWebhookDeliveries, len(expectedRunWebhookDeliveries)))
	assert.Assert(t, cmpDiffObject(runWebhookDeliveries, expectedRunWebhookDeliveries))
}

func cmpDiffObject(x, y interface{}) cmp.Comparison {
	// Since postgres has microsecond time precision while go has nanosecond time precision we should check times with a microsecond margin
	return cmp.DeepEqual(x, y, cmpopts.IgnoreFields(sqlg.ObjectMeta{}, "TxID"), cmpopts.EquateApproxTime(1*time.Microsecond))
}

func TestProjectRunWebhookRedelivery(t *testing.T) {
	t.Parallel()

	t.Run("test project run webhook redelivery with deliverystatus = deliveryError", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		runWebhook := createRunWebhook(t, ctx, ns, project01)
		runWebhookDelivery := createRunWebhookDelivery(t, ctx, ns, runWebhook.ID, types.DeliveryStatusDeliveryError)

		wr := setupWebhooksReceiver(ctx, t)
		defer wr.stop()

		t.Logf("starting webhooks client")

		ns.c.WebhookSecret = webhookSecret
		ns.c.WebhookURL = fmt.Sprintf("%s/%s", wr.exposedURL, "webhooks")

		err := ns.ah.RunWebhookRedelivery(ctx, runWebhook.ProjectID, runWebhookDelivery.ID)
		testutil.NilError(t, err)

		err = ns.runWebhookDeliveriesHandler(ctx)
		testutil.NilError(t, err)

		res, err := ns.ah.GetProjectRunWebhookDeliveries(ctx, &action.GetProjectRunWebhookDeliveriesRequest{ProjectID: project01, SortDirection: types.SortDirectionAsc})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(res.RunWebhookDeliveries, 2))
		assert.Assert(t, res.RunWebhookDeliveries[0].DeliveryStatus == types.DeliveryStatusDeliveryError)
		assert.Assert(t, res.RunWebhookDeliveries[1].DeliveryStatus == types.DeliveryStatusDelivered)
	})

	t.Run("test project run webhook redelivery with deliverystatus = delivered", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		runWebhook := createRunWebhook(t, ctx, ns, project01)
		runWebhookDelivery := createRunWebhookDelivery(t, ctx, ns, runWebhook.ID, types.DeliveryStatusDelivered)

		wr := setupWebhooksReceiver(ctx, t)
		defer wr.stop()

		t.Logf("starting webhooks client")

		ns.c.WebhookSecret = webhookSecret
		ns.c.WebhookURL = fmt.Sprintf("%s/%s", wr.exposedURL, "webhooks")

		err := ns.ah.RunWebhookRedelivery(ctx, runWebhook.ProjectID, runWebhookDelivery.ID)
		testutil.NilError(t, err)

		err = ns.runWebhookDeliveriesHandler(ctx)
		testutil.NilError(t, err)

		res, err := ns.ah.GetProjectRunWebhookDeliveries(ctx, &action.GetProjectRunWebhookDeliveriesRequest{ProjectID: project01, SortDirection: types.SortDirectionAsc})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(res.RunWebhookDeliveries, 2))
		assert.Assert(t, res.RunWebhookDeliveries[0].DeliveryStatus == types.DeliveryStatusDelivered)
		assert.Assert(t, res.RunWebhookDeliveries[1].DeliveryStatus == types.DeliveryStatusDelivered)
	})

	t.Run("test redelivery not existing project run webhook delivery", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		runWebhook := createRunWebhook(t, ctx, ns, project01)

		expectedErr := util.NewAPIError(util.ErrNotExist, errors.Errorf("runWebhookDelivery %q doesn't exist", runWebhookDelivery01))
		err := ns.ah.RunWebhookRedelivery(ctx, runWebhook.ProjectID, runWebhookDelivery01)
		assert.Error(t, err, expectedErr.Error())
	})

	t.Run("test project run webhook redelivery with projectID that belong to another project", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		runWebhook := createRunWebhook(t, ctx, ns, project01)
		runWebhookDelivery := createRunWebhookDelivery(t, ctx, ns, runWebhook.ID, types.DeliveryStatusDelivered)

		runWebhook = createRunWebhook(t, ctx, ns, project02)
		createRunWebhookDelivery(t, ctx, ns, runWebhook.ID, types.DeliveryStatusDelivered)

		expectedErr := util.NewAPIError(util.ErrNotExist, errors.Errorf("runWebhookDelivery %q doesn't belong to project %q", runWebhookDelivery.ID, project02))

		err := ns.ah.RunWebhookRedelivery(ctx, project02, runWebhookDelivery.ID)
		assert.Error(t, err, expectedErr.Error())
	})

	t.Run("test project run webhook redelivery with the last delivery that hasn't been delivered", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		runWebhook := createRunWebhook(t, ctx, ns, project01)
		runWebhookDelivery := createRunWebhookDelivery(t, ctx, ns, runWebhook.ID, types.DeliveryStatusNotDelivered)

		wr := setupWebhooksReceiver(ctx, t)
		defer wr.stop()

		t.Logf("starting webhooks client")

		ns.c.WebhookSecret = webhookSecret
		ns.c.WebhookURL = fmt.Sprintf("%s/%s", wr.exposedURL, "webhooks")

		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("the previous delivery of run webhook %q hasn't already been delivered", runWebhookDelivery.RunWebhookID))

		err := ns.ah.RunWebhookRedelivery(ctx, runWebhook.ProjectID, runWebhookDelivery.ID)
		assert.Error(t, err, expectedErr.Error())

		err = ns.runWebhookDeliveriesHandler(ctx)
		testutil.NilError(t, err)

		res, err := ns.ah.GetProjectRunWebhookDeliveries(ctx, &action.GetProjectRunWebhookDeliveriesRequest{ProjectID: project01, SortDirection: types.SortDirectionAsc})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(res.RunWebhookDeliveries, 1))
		assert.Assert(t, res.RunWebhookDeliveries[0].DeliveryStatus == types.DeliveryStatusDelivered)
	})
}

func TestCommitStatusesCleaner(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	log := testutil.NewLogger(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ns := setupNotificationService(ctx, t, log, dir)

	expectedCommitStatuses := make([]*types.CommitStatus, 0)
	expectedCommitStatusDeliveries := make([]*types.CommitStatusDelivery, 0)

	for i := 0; i < 5; i++ {
		commitStatus := createCommitStatus(t, ctx, ns, 1, fmt.Sprintf("projectID-%d", i))
		expectedCommitStatuses = append(expectedCommitStatuses, commitStatus)

		expectedCommitStatusDeliveries = append(expectedCommitStatusDeliveries, createCommitStatusDelivery(t, ctx, ns, commitStatus.ID, types.DeliveryStatusDelivered))
		expectedCommitStatusDeliveries = append(expectedCommitStatusDeliveries, createCommitStatusDelivery(t, ctx, ns, commitStatus.ID, types.DeliveryStatusNotDelivered))
	}

	commitStatusCreationTime := time.Now().Add(-1 * time.Hour)
	for i := 0; i < 50; i++ {
		commitStatus := createCommitStatus(t, ctx, ns, i, fmt.Sprintf("projectID-%d", i))
		createCommitStatusDelivery(t, ctx, ns, commitStatus.ID, types.DeliveryStatusDelivered)
		createCommitStatusDelivery(t, ctx, ns, commitStatus.ID, types.DeliveryStatusNotDelivered)

		updateCommitStatusCreationDate(t, ctx, ns, commitStatus.ID, commitStatusCreationTime)
	}

	err := ns.commitStatusesCleaner(ctx, 30*time.Minute)
	testutil.NilError(t, err)

	commitStatuses := getCommitStatuses(t, ctx, ns)
	assert.Assert(t, cmp.Len(commitStatuses, len(expectedCommitStatuses)))
	assert.Assert(t, cmpDiffObject(commitStatuses, expectedCommitStatuses))

	commitStatusDeliveries := getCommitStatusDeliveries(t, ctx, ns)
	testutil.NilError(t, err)

	assert.Assert(t, cmp.Len(commitStatusDeliveries, len(expectedCommitStatusDeliveries)))
	assert.Assert(t, cmpDiffObject(commitStatusDeliveries, expectedCommitStatusDeliveries))
}

func TestGetProjectCommitStatusDeliveries(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	log := testutil.NewLogger(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ns := setupNotificationService(ctx, t, log, dir)

	commitStatuses := make([]*types.CommitStatus, 10)
	project01CommitStatusDeliveries := make([]*types.CommitStatusDelivery, 0)
	for i := 0; i < len(commitStatuses); i++ {
		commitStatuses[i] = createCommitStatus(t, ctx, ns, i, project01)
		project01CommitStatusDeliveries = append(project01CommitStatusDeliveries, createCommitStatusDelivery(t, ctx, ns, commitStatuses[i].ID, types.DeliveryStatusDelivered))
		project01CommitStatusDeliveries = append(project01CommitStatusDeliveries, createCommitStatusDelivery(t, ctx, ns, commitStatuses[i].ID, types.DeliveryStatusNotDelivered))
	}

	for i := 0; i < len(commitStatuses); i++ {
		commitStatuses[i] = createCommitStatus(t, ctx, ns, i, project02)
		createCommitStatusDelivery(t, ctx, ns, commitStatuses[i].ID, types.DeliveryStatusDelivered)
		createCommitStatusDelivery(t, ctx, ns, commitStatuses[i].ID, types.DeliveryStatusNotDelivered)
	}

	tests := []struct {
		name                                 string
		limit                                int
		sortDirection                        types.SortDirection
		deliveryStatusFilter                 []types.DeliveryStatus
		expectedCommitStatusDeliveriesNumber int
		expectedCallsNumber                  int
	}{
		{
			name:                                 "test get commit status deliveries with limit = 0 and no sortdirection",
			expectedCommitStatusDeliveriesNumber: 20,
			expectedCallsNumber:                  1,
		},
		{
			name:                                 "test get commit status deliveries with limit = 0",
			sortDirection:                        types.SortDirectionAsc,
			expectedCommitStatusDeliveriesNumber: 20,
			expectedCallsNumber:                  1,
		},
		{
			name:                                 "test get commit status deliveries with deliverystatusfilter = delivered",
			sortDirection:                        types.SortDirectionAsc,
			deliveryStatusFilter:                 []types.DeliveryStatus{types.DeliveryStatusDelivered},
			expectedCommitStatusDeliveriesNumber: 10,
			expectedCallsNumber:                  1,
		},
		{
			name:                                 "test get commit status deliveries with deliverystatusfilter = delivered and limit less than commit status deliveries",
			limit:                                2,
			sortDirection:                        types.SortDirectionAsc,
			deliveryStatusFilter:                 []types.DeliveryStatus{types.DeliveryStatusDelivered},
			expectedCommitStatusDeliveriesNumber: 10,
			expectedCallsNumber:                  5,
		},
		{
			name:                                 "test get commit status deliveries with limit less than commit status deliveries",
			sortDirection:                        types.SortDirectionAsc,
			limit:                                5,
			expectedCommitStatusDeliveriesNumber: 20,
			expectedCallsNumber:                  4,
		},
		{
			name:                                 "test get commit status deliveries with limit = 0 and sortDirection desc",
			sortDirection:                        types.SortDirectionDesc,
			expectedCommitStatusDeliveriesNumber: 20,
			expectedCallsNumber:                  1,
		},
		{
			name:                                 "test get commit status deliveries with deliverystatusfilter = delivered and sortDirection desc",
			sortDirection:                        types.SortDirectionDesc,
			deliveryStatusFilter:                 []types.DeliveryStatus{types.DeliveryStatusDelivered},
			expectedCommitStatusDeliveriesNumber: 10,
			expectedCallsNumber:                  1,
		},
		{
			name:                                 "test get commit status deliveries with deliverystatusfilter = delivered and limit less than commit status deliveries and sortDirection desc",
			limit:                                2,
			sortDirection:                        types.SortDirectionDesc,
			deliveryStatusFilter:                 []types.DeliveryStatus{types.DeliveryStatusDelivered},
			expectedCommitStatusDeliveriesNumber: 10,
			expectedCallsNumber:                  5,
		},
		{
			name:                                 "test get commit status deliveries with limit less than commit status deliveries and sortDirection desc",
			sortDirection:                        types.SortDirectionDesc,
			limit:                                5,
			expectedCommitStatusDeliveriesNumber: 20,
			expectedCallsNumber:                  4,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// populate the expected commit status deliveries
			expectedProject01CommitStatusDeliveries := []*types.CommitStatusDelivery{}
			for _, c := range project01CommitStatusDeliveries {
				if len(tt.deliveryStatusFilter) > 0 && !deliveryStatusInSlice(tt.deliveryStatusFilter, c.DeliveryStatus) {
					continue
				}
				expectedProject01CommitStatusDeliveries = append(expectedProject01CommitStatusDeliveries, c)
			}
			// default sortdirection is asc

			// reverse if sortDirection is desc
			// TODO(sgotti) use go 1.21 generics slices.Reverse when removing support for go < 1.21
			if tt.sortDirection == types.SortDirectionDesc {
				for i, j := 0, len(expectedProject01CommitStatusDeliveries)-1; i < j; i, j = i+1, j-1 {
					expectedProject01CommitStatusDeliveries[i], expectedProject01CommitStatusDeliveries[j] = expectedProject01CommitStatusDeliveries[j], expectedProject01CommitStatusDeliveries[i]
				}
			}

			callsNumber := 0
			var lastProjectCommitStatusDelivery uint64
			var respAllProjectCommitStatusDeliveries []*types.CommitStatusDelivery

			// fetch next results
			for {
				res, err := ns.ah.GetProjectCommitStatusDeliveries(ctx, &action.GetProjectCommitStatusDeliveriesRequest{
					ProjectID:            project01,
					Limit:                tt.limit,
					SortDirection:        tt.sortDirection,
					DeliveryStatusFilter: tt.deliveryStatusFilter,
					StartSequence:        lastProjectCommitStatusDelivery,
				})
				testutil.NilError(t, err)

				callsNumber++

				respAllProjectCommitStatusDeliveries = append(respAllProjectCommitStatusDeliveries, res.CommitStatusDeliveries...)

				if res.HasMore == false {
					break
				}

				lastProjectCommitStatusDelivery = respAllProjectCommitStatusDeliveries[len(respAllProjectCommitStatusDeliveries)-1].Sequence
			}

			assert.Assert(t, cmpDiffObject(expectedProject01CommitStatusDeliveries, respAllProjectCommitStatusDeliveries))
			assert.Assert(t, cmp.Equal(callsNumber, tt.expectedCallsNumber))
		})
	}
}

// TODO(sgotti) use go 1.21 generics slices.Contains when removing support for go < 1.21
func deliveryStatusInSlice(deliveryStatuses []types.DeliveryStatus, deliveryStatus types.DeliveryStatus) bool {
	for _, s := range deliveryStatuses {
		if deliveryStatus == s {
			return true
		}
	}
	return false
}

func TestProjectCommitStatusRedelivery(t *testing.T) {
	t.Parallel()

	t.Run("test project commit status redelivery with deliverystatus = deliveryError", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		commitStatus := createCommitStatus(t, ctx, ns, 1, project01)
		commitStatusDelivery := createCommitStatusDelivery(t, ctx, ns, commitStatus.ID, types.DeliveryStatusDeliveryError)

		t.Logf("starting ns")

		cs := setupStubCommitStatusUpdater()
		ns.u = cs

		err := ns.ah.CommitStatusRedelivery(ctx, commitStatus.ProjectID, commitStatusDelivery.ID)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		if err := ns.commitStatusDeliveriesHandler(ctx); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		res, err := ns.ah.GetProjectCommitStatusDeliveries(ctx, &action.GetProjectCommitStatusDeliveriesRequest{ProjectID: project01, SortDirection: types.SortDirectionAsc})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(res.CommitStatusDeliveries) != 2 {
			t.Fatalf("expected 2 CommitStatusDeliveries got: %d", len(res.CommitStatusDeliveries))
		}
		if res.CommitStatusDeliveries[0].DeliveryStatus != types.DeliveryStatusDeliveryError {
			t.Fatalf("expected %q DeliveryStatus got: %q", types.DeliveryStatusDeliveryError, res.CommitStatusDeliveries[0].DeliveryStatus)
		}
		if res.CommitStatusDeliveries[1].DeliveryStatus != types.DeliveryStatusDelivered {
			t.Fatalf("expected %q DeliveryStatus got: %q", types.DeliveryStatusDelivered, res.CommitStatusDeliveries[1].DeliveryStatus)
		}
	})

	t.Run("test project commit status redelivery with deliverystatus = delivered", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		commitStatus := createCommitStatus(t, ctx, ns, 1, project01)
		commitStatusDelivery := createCommitStatusDelivery(t, ctx, ns, commitStatus.ID, types.DeliveryStatusDelivered)

		t.Logf("starting ns")

		cs := setupStubCommitStatusUpdater()
		ns.u = cs

		err := ns.ah.CommitStatusRedelivery(ctx, commitStatus.ProjectID, commitStatusDelivery.ID)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		if err := ns.commitStatusDeliveriesHandler(ctx); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		res, err := ns.ah.GetProjectCommitStatusDeliveries(ctx, &action.GetProjectCommitStatusDeliveriesRequest{ProjectID: project01, SortDirection: types.SortDirectionAsc})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(res.CommitStatusDeliveries) != 2 {
			t.Fatalf("expected 2 CommitStatusDeliveries got: %d", len(res.CommitStatusDeliveries))
		}
		if res.CommitStatusDeliveries[0].DeliveryStatus != types.DeliveryStatusDelivered {
			t.Fatalf("expected %q DeliveryStatus got: %q", types.DeliveryStatusDelivered, res.CommitStatusDeliveries[0].DeliveryStatus)
		}
		if res.CommitStatusDeliveries[1].DeliveryStatus != types.DeliveryStatusDelivered {
			t.Fatalf("expected %q DeliveryStatus got: %q", types.DeliveryStatusDelivered, res.CommitStatusDeliveries[1].DeliveryStatus)
		}
	})

	t.Run("test redelivery not existing project commit status delivery", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		commitStatus := createCommitStatus(t, ctx, ns, 1, project01)

		expectedErr := util.NewAPIError(util.ErrNotExist, errors.Errorf("commitStatusDelivery %q doesn't exist", commitStatusDelivery01))
		err := ns.ah.CommitStatusRedelivery(ctx, commitStatus.ProjectID, commitStatusDelivery01)
		if err == nil {
			t.Fatalf("expected error %v, got nil err", expectedErr)
		}
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})

	t.Run("test project commit status redelivery with projectID that belong to another project", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		commitStatus := createCommitStatus(t, ctx, ns, 1, project01)
		commitStatusDelivery := createCommitStatusDelivery(t, ctx, ns, commitStatus.ID, types.DeliveryStatusDelivered)

		commitStatus = createCommitStatus(t, ctx, ns, 1, project02)
		createCommitStatusDelivery(t, ctx, ns, commitStatus.ID, types.DeliveryStatusDelivered)

		expectedErr := util.NewAPIError(util.ErrNotExist, errors.Errorf("commitStatusDelivery %q doesn't belong to project %q", commitStatusDelivery.ID, project02))

		err := ns.ah.CommitStatusRedelivery(ctx, project02, commitStatusDelivery.ID)
		if err == nil {
			t.Fatalf("expected error %v, got nil err", expectedErr)
		}
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})

	t.Run("test project commit status redelivery with the last delivery that hasn't been delivered", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		commitStatus := createCommitStatus(t, ctx, ns, 1, project01)
		commitStatusDelivery := createCommitStatusDelivery(t, ctx, ns, commitStatus.ID, types.DeliveryStatusNotDelivered)

		t.Logf("starting ns")

		cs := setupStubCommitStatusUpdater()
		ns.u = cs

		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("the previous delivery of commit status %q hasn't already been delivered", commitStatusDelivery.CommitStatusID))

		err := ns.ah.CommitStatusRedelivery(ctx, commitStatus.ProjectID, commitStatusDelivery.ID)
		if err == nil {
			t.Fatalf("expected error %v, got nil err", expectedErr)
		}
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}

		if err := ns.commitStatusDeliveriesHandler(ctx); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		res, err := ns.ah.GetProjectCommitStatusDeliveries(ctx, &action.GetProjectCommitStatusDeliveriesRequest{ProjectID: project01, SortDirection: types.SortDirectionAsc})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(res.CommitStatusDeliveries) != 1 {
			t.Fatalf("expected 1 CommitStatusDeliveries got: %d", len(res.CommitStatusDeliveries))
		}
		if res.CommitStatusDeliveries[0].DeliveryStatus != types.DeliveryStatusDelivered {
			t.Fatalf("expected %q DeliveryStatus got: %q", types.DeliveryStatusDelivered, res.CommitStatusDeliveries[0].DeliveryStatus)
		}
	})
}
