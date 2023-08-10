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
	"fmt"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/testutil"
	"agola.io/agola/services/notification/types"
)

const (
	webhookSecret  = "secretkey"
	webhookPayload = "payloadtest"
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
