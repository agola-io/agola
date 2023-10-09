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

	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/testutil"
	"agola.io/agola/services/notification/types"
	rsclient "agola.io/agola/services/runservice/client"
	rstypes "agola.io/agola/services/runservice/types"
)

const (
	webhookSecret  = "secretkey"
	webhookPayload = "payloadtest"
	webhookURL     = "testWebhookURL"
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

		t.Logf("starting ns")

		time.Sleep(1 * time.Second)

		wr := setupWebhooksReceiver(ctx, t)
		defer wr.stop()

		t.Logf("starting webhooks client")

		ns.c.WebhookURL = fmt.Sprintf("%s/%s", wr.exposedURL, "webhooks")
		ns.c.WebhookSecret = webhookSecret

		runWebhooks := make([]*types.RunWebhook, MaxRunWebhookDeliveriesQueryLimit+10)
		for i := 0; i < len(runWebhooks); i++ {
			runWebhooks[i] = createRunWebhook(t, ctx, ns)
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

		t.Logf("starting ns")

		time.Sleep(1 * time.Second)

		runWebhook := createRunWebhook(t, ctx, ns)
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
		wd, err = ns.d.GetRunWebhookDeliveriesAfterSequence(tx, 0, "", 0)
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

func createRunWebhook(t *testing.T, ctx context.Context, ns *NotificationService) *types.RunWebhook {
	var wh *types.RunWebhook

	err := ns.d.Do(ctx, func(tx *sql.Tx) error {
		wh = types.NewRunWebhook(tx)
		wh.Payload = []byte(webhookPayload)

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
			commitStatuses[i] = createCommitStatus(t, ctx, ns, i)
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

		commitStatus := createCommitStatus(t, ctx, ns, 1)
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

func createCommitStatus(t *testing.T, ctx context.Context, ns *NotificationService, n int) *types.CommitStatus {
	var cs *types.CommitStatus

	err := ns.d.Do(ctx, func(tx *sql.Tx) error {
		cs = types.NewCommitStatus(tx)
		cs.CommitSHA = fmt.Sprintf("commitSHA-%d", n)
		cs.Context = fmt.Sprintf("context-%d", n)
		cs.Description = "The run finished successfully"
		cs.ProjectID = fmt.Sprintf("projectID-%d", n)
		cs.RunCounter = uint64(n)
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

func getCommitStatusDeliveries(t *testing.T, ctx context.Context, ns *NotificationService) []*types.CommitStatusDelivery {
	var wd []*types.CommitStatusDelivery

	err := ns.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		wd, err = ns.d.GetCommitStatusDeliveriesAfterSequence(tx, 0, "", 0)
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
