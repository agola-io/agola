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

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

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
	webhookSecret        = "secretkey"
	webhookPayload       = "payloadtest"
	webhookURL           = "testWebhookURL"
	project01            = "project01id"
	project02            = "project02id"
	runWebhookDelivery01 = "runwebhookdelivery01id"
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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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

		if err := ns.runWebhookDeliveriesHandler(ctx); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		runWebhookDeliveries := getRunWebhookDeliveries(t, ctx, ns)
		if len(runWebhookDeliveries) != len(runWebhooks) {
			t.Fatalf("expected %d runWebhook deliveries got: %d", len(runWebhooks), len(runWebhookDeliveries))
		}
		for i := 0; i < len(runWebhookDeliveries); i++ {
			if runWebhookDeliveries[i].DeliveryStatus != types.DeliveryStatusDelivered {
				t.Fatalf("expected runWebhook delivery status %q, got %q", types.DeliveryStatusDelivered, runWebhookDeliveries[i].DeliveryStatus)
			}
		}

		webhooks, err := wr.webhooks.getWebhooks()
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(webhooks) != len(runWebhooks) {
			t.Fatalf("expected %d run webhook got: %d", len(runWebhooks), len(webhooks))
		}
		for i := 0; i < len(runWebhookDeliveries); i++ {
			if !bytes.Equal(webhooks[i].Payload, runWebhooks[i].Payload) {
				t.Fatalf("expected %s run webhook payload got: %s", runWebhooks[i].Payload, webhooks[i].Payload)
			}

			h256 := hmac.New(sha256.New, []byte(webhookSecret))
			if _, err = h256.Write([]byte(runWebhooks[i].Payload)); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			expectedsignature := hex.EncodeToString(h256.Sum(nil))

			if webhooks[i].Signature != expectedsignature {
				t.Fatalf("expected %s run webhook signature got: %s", expectedsignature, webhooks[i].Signature)
			}
		}

		// test run webhooks handled previously.

		wr.webhooks.resetWebhooks()

		if err := ns.runWebhookDeliveriesHandler(ctx); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		webhooks, err = wr.webhooks.getWebhooks()
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(webhooks) != 0 {
			t.Fatalf("expected %d run webhook got: %d", 0, len(webhooks))
		}
	})

	t.Run("test run webhook delivery fail", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		runWebhook := createRunWebhook(t, ctx, ns, project01)
		createRunWebhookDelivery(t, ctx, ns, runWebhook.ID, types.DeliveryStatusNotDelivered)

		if err := ns.runWebhookDeliveriesHandler(ctx); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		runWebhookDeliveries := getRunWebhookDeliveries(t, ctx, ns)
		if len(runWebhookDeliveries) != 1 {
			t.Fatalf("expected %d runWebhook deliveries got: %d", 1, len(runWebhookDeliveries))
		}
		if runWebhookDeliveries[0].DeliveryStatus != types.DeliveryStatusDeliveryError {
			t.Fatalf("expected runWebhook delivery status %q, got %q", types.DeliveryStatusDeliveryError, runWebhookDeliveries[0].DeliveryStatus)
		}
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

	t.Logf("starting ns")

	runEventsSender := setupRunEventsSender(ctx, t)
	defer runEventsSender.stop()

	t.Logf("starting run events service")

	ns.runserviceClient = rsclient.NewClient(runEventsSender.exposedURL, "")

	lastRunEventSequenceValue := getLastRunEventSequenceValue(t, ctx, ns)
	if lastRunEventSequenceValue != 0 {
		t.Fatalf("expected lastRunEventSequence %d, got: %d", 0, lastRunEventSequenceValue)
	}

	// test runEventsHandler start from sequence 0
	runEvents := make([]*rstypes.RunEvent, 0)
	runEvents = append(runEvents, generateRunEvent(1, rstypes.RunPhaseChanged))
	runEvents = append(runEvents, generateRunEvent(2, rstypes.RunPhaseChanged))

	runEventsSender.runEvents.addRunEvent(runEvents[0])
	runEventsSender.runEvents.addRunEvent(runEvents[1])
	expectedLastRunEventSequenceValue := uint64(2)

	err := ns.runEventsHandler(ctx)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	lastRunEventSequenceValue = getLastRunEventSequenceValue(t, ctx, ns)
	if lastRunEventSequenceValue != expectedLastRunEventSequenceValue {
		t.Fatalf("expected %d last run event got: %d", expectedLastRunEventSequenceValue, lastRunEventSequenceValue)
	}

	// test new events
	runEvents = append(runEvents, generateRunEvent(3, rstypes.RunPhaseChanged))
	runEvents = append(runEvents, generateRunEvent(4, rstypes.RunPhaseChanged))

	runEventsSender.runEvents.addRunEvent(runEvents[2])
	runEventsSender.runEvents.addRunEvent(runEvents[3])

	err = ns.runEventsHandler(ctx)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	runWebhooks := getRunWebhooks(t, ctx, ns)
	if len(runWebhooks) != len(runEvents) {
		t.Fatalf("expected %d runWebhooks got: %d", len(runEvents), len(runWebhooks))
	}

	for i := range runEvents {
		runWebhook := ns.generatewebhook(ctx, runEvents[i])
		webhookPayload, err := json.Marshal(runWebhook)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		if !bytes.Equal(runWebhooks[i].Payload, webhookPayload) {
			t.Fatalf("expected %s run webhook payload got: %s", runWebhooks[i].Payload, webhookPayload)
		}
	}

	expectedLastRunEventSequenceValue = 4
	lastRunEventSequenceValue = getLastRunEventSequenceValue(t, ctx, ns)
	if lastRunEventSequenceValue != expectedLastRunEventSequenceValue {
		t.Fatalf("expected %d last run event sequence got: %d", expectedLastRunEventSequenceValue, lastRunEventSequenceValue)
	}
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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestCommitStatusDelivery(t *testing.T) {
	t.Parallel()

	t.Run("test commit status delivery success", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		t.Logf("starting ns")

		cs := setupStubCommitStatusUpdater()
		ns.u = cs

		commitStatuses := make([]*types.CommitStatus, MaxCommitStatusDeliveriesQueryLimit+10)
		for i := 0; i < len(commitStatuses); i++ {
			commitStatuses[i] = createCommitStatus(t, ctx, ns, i, fmt.Sprintf("projectID-%d", i))
			createCommitStatusDelivery(t, ctx, ns, commitStatuses[i].ID, types.DeliveryStatusNotDelivered)
		}

		if err := ns.commitStatusDeliveriesHandler(ctx); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		commitStatusDeliveries := getCommitStatusDeliveries(t, ctx, ns)
		if len(commitStatusDeliveries) != len(commitStatuses) {
			t.Fatalf("expected %d commitStatus deliveries got: %d", len(commitStatuses), len(commitStatusDeliveries))
		}
		for i := 0; i < len(commitStatusDeliveries); i++ {
			if commitStatusDeliveries[i].DeliveryStatus != types.DeliveryStatusDelivered {
				t.Fatalf("expected commitStatus delivery status %q, got %q", types.DeliveryStatusDelivered, commitStatusDeliveries[i].DeliveryStatus)
			}
		}

		commitStatusesReceived, err := cs.commitStatuses.getCommitStatuses()
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(commitStatusesReceived) != len(commitStatuses) {
			t.Fatalf("expected %d run commitStatus got: %d", len(commitStatuses), len(commitStatusesReceived))
		}
		for i := 0; i < len(commitStatuses); i++ {
			if commitStatusesReceived[i].Context != commitStatuses[i].Context {
				t.Fatalf("expected %s commitStatus context got: %s", commitStatuses[i].Context, commitStatusesReceived[i].Context)
			}

			if commitStatusesReceived[i].Description != commitStatuses[i].Description {
				t.Fatalf("expected %s commitStatus description got: %s", commitStatuses[i].Description, commitStatusesReceived[i].Description)
			}

			if commitStatusesReceived[i].State != commitStatuses[i].State {
				t.Fatalf("expected %s commitStatus sate got: %s", commitStatuses[i].State, commitStatusesReceived[i].State)
			}
		}

		// test commitstatuses handled previously.

		cs.commitStatuses.resetCommitStatuses()

		if err := ns.commitStatusDeliveriesHandler(ctx); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		commitStatusesReceived, err = cs.commitStatuses.getCommitStatuses()
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(commitStatusesReceived) != 0 {
			t.Fatalf("expected %d commit status got: %d", 0, len(commitStatusesReceived))
		}
	})

	t.Run("test commit status delivery fail", func(t *testing.T) {
		dir := t.TempDir()
		log := testutil.NewLogger(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ns := setupNotificationService(ctx, t, log, dir)

		t.Logf("starting ns")

		s := setupStubCommitStatusUpdater()
		s.setFailUpdateCommitStatus(true)
		ns.u = s

		commitStatus := createCommitStatus(t, ctx, ns, 1, project01)
		createCommitStatusDelivery(t, ctx, ns, commitStatus.ID, types.DeliveryStatusNotDelivered)

		if err := ns.commitStatusDeliveriesHandler(ctx); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		commitStatusDeliveries := getCommitStatusDeliveries(t, ctx, ns)
		if len(commitStatusDeliveries) != 1 {
			t.Fatalf("expected %d commitStatus deliveries got: %d", 1, len(commitStatusDeliveries))
		}
		if commitStatusDeliveries[0].DeliveryStatus != types.DeliveryStatusDeliveryError {
			t.Fatalf("expected commitStatus delivery status %q, got %q", types.DeliveryStatusDeliveryError, commitStatusDeliveries[0].DeliveryStatus)
		}
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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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

	t.Run("test get run webhook deliveries with limit = 0", func(t *testing.T) {
		res, err := ns.ah.GetProjectRunWebhookDeliveries(ctx, &action.GetProjectRunWebhookDeliveriesRequest{ProjectID: project01, Limit: 0})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if res.HasMore != false {
			t.Fatalf("unexpected HasMore true")
		}
		if len(res.RunWebhookDeliveries) != 20 {
			t.Fatalf("unexpected 20 run webhook deliveries, got %d", len(res.RunWebhookDeliveries))
		}
	})

	t.Run("test get run webhook deliveries with limit = 10", func(t *testing.T) {
		res, err := ns.ah.GetProjectRunWebhookDeliveries(ctx, &action.GetProjectRunWebhookDeliveriesRequest{ProjectID: project01, Limit: 10})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if res.HasMore != true {
			t.Fatalf("unexpected HasMore false")
		}
		if len(res.RunWebhookDeliveries) != 10 {
			t.Fatalf("unexpected 10 run webhook deliveries, got %d", len(res.RunWebhookDeliveries))
		}
	})

	t.Run("test get run webhook deliveries with deliverystatusfilter = delivered", func(t *testing.T) {
		res, err := ns.ah.GetProjectRunWebhookDeliveries(ctx, &action.GetProjectRunWebhookDeliveriesRequest{ProjectID: project01, DeliveryStatusFilter: []types.DeliveryStatus{types.DeliveryStatusDelivered}, Limit: 0})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if res.HasMore != false {
			t.Fatalf("unexpected HasMore true")
		}
		if len(res.RunWebhookDeliveries) != 10 {
			t.Fatalf("unexpected 10 run webhook deliveries, got %d", len(res.RunWebhookDeliveries))
		}
	})

	t.Run("test get run webhook deliveries with deliverystatusfilter = delivered and limit less than run webhook deliveries", func(t *testing.T) {
		res, err := ns.ah.GetProjectRunWebhookDeliveries(ctx, &action.GetProjectRunWebhookDeliveriesRequest{ProjectID: project01, DeliveryStatusFilter: []types.DeliveryStatus{types.DeliveryStatusDelivered}, Limit: 5})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if res.HasMore != true {
			t.Fatalf("unexpected HasMore false")
		}
		if len(res.RunWebhookDeliveries) != 5 {
			t.Fatalf("unexpected 5 run webhook deliveries, got %d", len(res.RunWebhookDeliveries))
		}
	})

	t.Run("test get run webhook deliveries with limit less than run webhook deliveries continuation", func(t *testing.T) {
		respAllProjectRunWebhookDeliveries := []*types.RunWebhookDelivery{}

		res, err := ns.ah.GetProjectRunWebhookDeliveries(ctx, &action.GetProjectRunWebhookDeliveriesRequest{ProjectID: project01, Limit: 5, SortDirection: types.SortDirectionAsc})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		expectedProjectRunWebhookDeliveries := 5
		if len(res.RunWebhookDeliveries) != expectedProjectRunWebhookDeliveries {
			t.Fatalf("expected %d project run webhook deliveries, got %d project run webhook deliveries", expectedProjectRunWebhookDeliveries, len(res.RunWebhookDeliveries))
		}
		if !res.HasMore {
			t.Fatalf("expected hasMore true, got %t", res.HasMore)
		}

		respAllProjectRunWebhookDeliveries = append(respAllProjectRunWebhookDeliveries, res.RunWebhookDeliveries...)
		lastProjectRunWebhookDelivery := res.RunWebhookDeliveries[len(res.RunWebhookDeliveries)-1]

		// fetch next results
		for {
			res, err = ns.ah.GetProjectRunWebhookDeliveries(ctx, &action.GetProjectRunWebhookDeliveriesRequest{ProjectID: project01, StartSequence: lastProjectRunWebhookDelivery.Sequence, Limit: 5, SortDirection: types.SortDirectionAsc})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			if res.HasMore && len(res.RunWebhookDeliveries) != expectedProjectRunWebhookDeliveries {
				t.Fatalf("expected %d project run webhook deliveries, got %d project run webhook deliveries", expectedProjectRunWebhookDeliveries, len(res.RunWebhookDeliveries))
			}

			respAllProjectRunWebhookDeliveries = append(respAllProjectRunWebhookDeliveries, res.RunWebhookDeliveries...)

			if !res.HasMore {
				break
			}

			lastProjectRunWebhookDelivery = res.RunWebhookDeliveries[len(res.RunWebhookDeliveries)-1]
		}

		expectedProjectRunWebhookDeliveries = 20
		if len(respAllProjectRunWebhookDeliveries) != expectedProjectRunWebhookDeliveries {
			t.Fatalf("expected %d project run webhook deliveries, got %d project run webhook deliveries", expectedProjectRunWebhookDeliveries, len(respAllProjectRunWebhookDeliveries))
		}

		if diff := cmpDiffObject(project01RunWebhookDeliveries, respAllProjectRunWebhookDeliveries); diff != "" {
			t.Fatalf("mismatch (-want +got):\n%s", diff)
		}
	})
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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(result, expectedDeliveryStatus); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}

	// test wrong deliverystatus
	baddeliverystatus := "baddeliverystatus"
	deliverystatus = []string{string(types.DeliveryStatusNotDelivered), string(types.DeliveryStatusDelivered), string(types.DeliveryStatusDeliveryError), baddeliverystatus}
	_, err = types.DeliveryStatusFromStringSlice(deliverystatus)
	expectedErr := fmt.Sprintf("invalid delivery status %q", baddeliverystatus)
	if err == nil {
		t.Fatalf("expected error %v, got nil err", expectedErr)
	}
	if err.Error() != expectedErr {
		t.Fatalf("expected err %v, got err: %v", expectedErr, err)
	}
}

func TestRunWebhooksCleaner(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	log := testutil.NewLogger(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ns := setupNotificationService(ctx, t, log, dir)

	t.Logf("starting ns")

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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	runWebhooks := getRunWebhooks(t, ctx, ns)
	if len(runWebhooks) != len(expectedRunWebhooks) {
		t.Fatalf("expected %d run webhooks got: %d", len(expectedRunWebhooks), len(runWebhooks))
	}
	if diff := cmpDiffObject(runWebhooks, expectedRunWebhooks); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}

	runWebhookDeliveries := getRunWebhookDeliveries(t, ctx, ns)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(runWebhookDeliveries) != len(expectedRunWebhookDeliveries) {
		t.Fatalf("expected %d run webhooks got: %d", len(expectedRunWebhookDeliveries), len(runWebhookDeliveries))
	}
	if diff := cmpDiffObject(runWebhookDeliveries, expectedRunWebhookDeliveries); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}
}

func cmpDiffObject(x, y interface{}) string {
	// Since postgres has microsecond time precision while go has nanosecond time precision we should check times with a microsecond margin
	return cmp.Diff(x, y, cmpopts.IgnoreFields(sqlg.ObjectMeta{}, "TxID"), cmpopts.EquateApproxTime(1*time.Microsecond))
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
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		if err := ns.runWebhookDeliveriesHandler(ctx); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		res, err := ns.ah.GetProjectRunWebhookDeliveries(ctx, &action.GetProjectRunWebhookDeliveriesRequest{ProjectID: project01, SortDirection: types.SortDirectionAsc})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(res.RunWebhookDeliveries) != 2 {
			t.Fatalf("expected 2 RunWebhookDeliveries got: %d", len(res.RunWebhookDeliveries))
		}
		if res.RunWebhookDeliveries[0].DeliveryStatus != types.DeliveryStatusDeliveryError {
			t.Fatalf("expected %q DeliveryStatus got: %q", types.DeliveryStatusDeliveryError, res.RunWebhookDeliveries[0].DeliveryStatus)
		}
		if res.RunWebhookDeliveries[1].DeliveryStatus != types.DeliveryStatusDelivered {
			t.Fatalf("expected %q DeliveryStatus got: %q", types.DeliveryStatusDelivered, res.RunWebhookDeliveries[1].DeliveryStatus)
		}
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
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		if err := ns.runWebhookDeliveriesHandler(ctx); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		res, err := ns.ah.GetProjectRunWebhookDeliveries(ctx, &action.GetProjectRunWebhookDeliveriesRequest{ProjectID: project01, SortDirection: types.SortDirectionAsc})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(res.RunWebhookDeliveries) != 2 {
			t.Fatalf("expected 2 RunWebhookDeliveries got: %d", len(res.RunWebhookDeliveries))
		}
		if res.RunWebhookDeliveries[0].DeliveryStatus != types.DeliveryStatusDelivered {
			t.Fatalf("expected %q DeliveryStatus got: %q", types.DeliveryStatusDelivered, res.RunWebhookDeliveries[0].DeliveryStatus)
		}
		if res.RunWebhookDeliveries[1].DeliveryStatus != types.DeliveryStatusDelivered {
			t.Fatalf("expected %q DeliveryStatus got: %q", types.DeliveryStatusDelivered, res.RunWebhookDeliveries[1].DeliveryStatus)
		}
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
		if err == nil {
			t.Fatalf("expected error %v, got nil err", expectedErr)
		}
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
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
		if err == nil {
			t.Fatalf("expected error %v, got nil err", expectedErr)
		}
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
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
		if err == nil {
			t.Fatalf("expected error %v, got nil err", expectedErr)
		}
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}

		if err := ns.runWebhookDeliveriesHandler(ctx); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		res, err := ns.ah.GetProjectRunWebhookDeliveries(ctx, &action.GetProjectRunWebhookDeliveriesRequest{ProjectID: project01, SortDirection: types.SortDirectionAsc})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(res.RunWebhookDeliveries) != 1 {
			t.Fatalf("expected 1 RunWebhookDeliveries got: %d", len(res.RunWebhookDeliveries))
		}
		if res.RunWebhookDeliveries[0].DeliveryStatus != types.DeliveryStatusDelivered {
			t.Fatalf("expected %q DeliveryStatus got: %q", types.DeliveryStatusDelivered, res.RunWebhookDeliveries[0].DeliveryStatus)
		}
	})
}

func TestCommitStatusesCleaner(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	log := testutil.NewLogger(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ns := setupNotificationService(ctx, t, log, dir)

	t.Logf("starting ns")

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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	commitStatuses := getCommitStatuses(t, ctx, ns)
	if len(commitStatuses) != len(expectedCommitStatuses) {
		t.Fatalf("expected %d run commitStatuses got: %d", len(expectedCommitStatuses), len(commitStatuses))
	}
	if diff := cmpDiffObject(commitStatuses, expectedCommitStatuses); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}

	commitStatusDeliveries := getCommitStatusDeliveries(t, ctx, ns)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(commitStatusDeliveries) != len(expectedCommitStatusDeliveries) {
		t.Fatalf("expected %d run commitStatusDeliveries got: %d", len(expectedCommitStatusDeliveries), len(commitStatusDeliveries))
	}
	if diff := cmpDiffObject(commitStatusDeliveries, expectedCommitStatusDeliveries); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}
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

	t.Run("test get commit status deliveries with limit = 0", func(t *testing.T) {
		res, err := ns.ah.GetProjectCommitStatusDeliveries(ctx, &action.GetProjectCommitStatusDeliveriesRequest{ProjectID: project01, Limit: 0})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if res.HasMore != false {
			t.Fatalf("unexpected HasMore true")
		}
		if len(res.CommitStatusDeliveries) != 20 {
			t.Fatalf("expected 20 commit status deliveries, got %d", len(res.CommitStatusDeliveries))
		}
	})

	t.Run("test get commit status deliveries with limit = 10", func(t *testing.T) {
		res, err := ns.ah.GetProjectCommitStatusDeliveries(ctx, &action.GetProjectCommitStatusDeliveriesRequest{ProjectID: project01, Limit: 10})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if res.HasMore != true {
			t.Fatalf("unexpected HasMore false")
		}
		if len(res.CommitStatusDeliveries) != 10 {
			t.Fatalf("expected 10 commit status deliveries, got %d", len(res.CommitStatusDeliveries))
		}
	})

	t.Run("test get commit status deliveries with deliverystatusfilter = delivered", func(t *testing.T) {
		res, err := ns.ah.GetProjectCommitStatusDeliveries(ctx, &action.GetProjectCommitStatusDeliveriesRequest{ProjectID: project01, DeliveryStatusFilter: []types.DeliveryStatus{types.DeliveryStatusDelivered}, Limit: 0})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if res.HasMore != false {
			t.Fatalf("unexpected HasMore true")
		}
		if len(res.CommitStatusDeliveries) != 10 {
			t.Fatalf("expected 10 commit status deliveries, got %d", len(res.CommitStatusDeliveries))
		}
	})

	t.Run("test get commit status deliveries with deliverystatusfilter = delivered and limit less than commit status deliveries", func(t *testing.T) {
		res, err := ns.ah.GetProjectCommitStatusDeliveries(ctx, &action.GetProjectCommitStatusDeliveriesRequest{ProjectID: project01, DeliveryStatusFilter: []types.DeliveryStatus{types.DeliveryStatusDelivered}, Limit: 5})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if res.HasMore != true {
			t.Fatalf("unexpected HasMore false")
		}
		if len(res.CommitStatusDeliveries) != 5 {
			t.Fatalf("expected 5 commit status deliveries, got %d", len(res.CommitStatusDeliveries))
		}
	})

	t.Run("test get commit status deliveries with limit less than commit status deliveries continuation", func(t *testing.T) {
		respAllProjectCommitStatusDeliveries := []*types.CommitStatusDelivery{}

		res, err := ns.ah.GetProjectCommitStatusDeliveries(ctx, &action.GetProjectCommitStatusDeliveriesRequest{ProjectID: project01, Limit: 5, SortDirection: types.SortDirectionAsc})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		expectedProjectCommitStatusDeliveries := 5
		if len(res.CommitStatusDeliveries) != expectedProjectCommitStatusDeliveries {
			t.Fatalf("expected %d project commit status deliveries, got %d project commit status deliveries", expectedProjectCommitStatusDeliveries, len(res.CommitStatusDeliveries))
		}
		if !res.HasMore {
			t.Fatalf("expected hasMore true, got %t", res.HasMore)
		}

		respAllProjectCommitStatusDeliveries = append(respAllProjectCommitStatusDeliveries, res.CommitStatusDeliveries...)
		lastProjectCommitStatusDelivery := res.CommitStatusDeliveries[len(res.CommitStatusDeliveries)-1]

		// fetch next results
		for {
			res, err = ns.ah.GetProjectCommitStatusDeliveries(ctx, &action.GetProjectCommitStatusDeliveriesRequest{ProjectID: project01, StartSequence: lastProjectCommitStatusDelivery.Sequence, Limit: 5, SortDirection: types.SortDirectionAsc})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			if res.HasMore && len(res.CommitStatusDeliveries) != expectedProjectCommitStatusDeliveries {
				t.Fatalf("expected %d project commit status deliveries, got %d project commit status deliveries", expectedProjectCommitStatusDeliveries, len(res.CommitStatusDeliveries))
			}

			respAllProjectCommitStatusDeliveries = append(respAllProjectCommitStatusDeliveries, res.CommitStatusDeliveries...)

			if !res.HasMore {
				break
			}

			lastProjectCommitStatusDelivery = res.CommitStatusDeliveries[len(res.CommitStatusDeliveries)-1]
		}

		expectedProjectCommitStatusDeliveries = 20
		if len(respAllProjectCommitStatusDeliveries) != expectedProjectCommitStatusDeliveries {
			t.Fatalf("expected %d project commit status deliveries, got %d project commit status deliveries", expectedProjectCommitStatusDeliveries, len(respAllProjectCommitStatusDeliveries))
		}

		if diff := cmpDiffObject(project01CommitStatusDeliveries, respAllProjectCommitStatusDeliveries); diff != "" {
			t.Fatalf("mismatch (-want +got):\n%s", diff)
		}
	})
}
