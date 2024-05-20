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
	"net/http"
	"time"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/sqlg/lock"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/notification/types"
)

const (
	maxRunWebhookDeliveriesQueryLimit = 40
	RunWebhookDeliveriesLockKey       = "runwebhookdeliveryevents"

	// runWebhookDeliveriesInterval is the time to wait between every runWebhookDeliveriesHandler call.
	runWebhookDeliveriesInterval = time.Second * 1
)

func (n *NotificationService) RunWebhookDeliveriesHandlerLoop(ctx context.Context) {
	for {
		if err := n.runWebhookDeliveriesHandler(ctx); err != nil {
			n.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(runWebhookDeliveriesInterval).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (n *NotificationService) runWebhookDeliveriesHandler(ctx context.Context) error {
	l := n.lf.NewLock(RunWebhookDeliveriesLockKey)
	if err := l.TryLock(ctx); err != nil {
		if errors.Is(err, lock.ErrLocked) {
			return nil
		}
		return errors.WithStack(err)
	}
	defer func() { _ = l.Unlock() }()

	curRunWebhookDeliverySequence := uint64(0)

	for {
		var runWebhookDeliveries []*types.RunWebhookDelivery

		err := n.d.Do(ctx, func(tx *sql.Tx) error {
			var err error
			runWebhookDeliveries, err = n.d.GetProjectRunWebhookDeliveriesAfterSequenceByProjectID(tx, curRunWebhookDeliverySequence, "", []types.DeliveryStatus{types.DeliveryStatusNotDelivered}, maxRunWebhookDeliveriesQueryLimit, types.SortDirectionAsc)
			if err != nil {
				return errors.WithStack(err)
			}

			return nil
		})
		if err != nil {
			return errors.WithStack(err)
		}

		for _, r := range runWebhookDeliveries {
			if err := n.handleRunWebhookDelivery(ctx, r.ID); err != nil {
				n.log.Err(err).Msgf("failed to trigger run webhook delivery event")
			}

			curRunWebhookDeliverySequence = r.Sequence
		}

		if len(runWebhookDeliveries) < maxRunWebhookDeliveriesQueryLimit {
			return nil
		}
	}
}

func (n *NotificationService) handleRunWebhookDelivery(ctx context.Context, runWebhookDeliveryID string) error {
	var runWebhook *types.RunWebhook

	err := n.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		runWebhookDelivery, err := n.d.GetRunWebhookDeliveryByID(tx, runWebhookDeliveryID)
		if err != nil {
			return errors.WithStack(err)
		}

		if runWebhookDelivery.DeliveryStatus != types.DeliveryStatusNotDelivered {
			return nil
		}

		runWebhook, err = n.d.GetRunWebhookByID(tx, runWebhookDelivery.RunWebhookID)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}
	if runWebhook == nil {
		return nil
	}

	webhookDelivered := false
	resp, err := n.sendRunWebhook(ctx, runWebhook.Payload, runWebhook.ID)
	// err != nil is not checked because every error is considered a failed delivery
	if err == nil && resp != nil && resp.StatusCode == http.StatusCreated {
		webhookDelivered = true
	}

	var deliveredAt *time.Time
	var statusCode int

	if resp != nil {
		deliveredAt = util.Ptr(time.Now())
		statusCode = resp.StatusCode
	}

	err = n.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		runWebhookDelivery, err := n.d.GetRunWebhookDeliveryByID(tx, runWebhookDeliveryID)
		if err != nil {
			return errors.WithStack(err)
		}
		if runWebhookDelivery.DeliveryStatus != types.DeliveryStatusNotDelivered {
			return nil
		}

		if webhookDelivered {
			runWebhookDelivery.DeliveryStatus = types.DeliveryStatusDelivered
		} else {
			runWebhookDelivery.DeliveryStatus = types.DeliveryStatusDeliveryError
		}

		runWebhookDelivery.DeliveredAt = deliveredAt
		runWebhookDelivery.StatusCode = statusCode

		if err = n.d.UpdateRunWebhookDelivery(tx, runWebhookDelivery); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (n *NotificationService) sendRunWebhook(ctx context.Context, webhookPayload []byte, runWebhookUUID string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", n.c.WebhookURL, bytes.NewReader(webhookPayload))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(agolaEventHeader, string(AgolaEventRun))
	req.Header.Add(agolaDeliveryHeader, runWebhookUUID)

	if n.c.WebhookSecret != "" {
		h256 := hmac.New(sha256.New, []byte(n.c.WebhookSecret))
		if _, err = h256.Write(webhookPayload); err != nil {
			return nil, errors.WithStack(err)
		}

		signatureSHA256 := hex.EncodeToString(h256.Sum(nil))

		req.Header.Set(signatureSHA256Key, signatureSHA256)
	}

	resp, err := http.DefaultClient.Do(req)

	return resp, errors.WithStack(err)
}
