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

package notification

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/sqlg/lock"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/services/notification/types"
	rstypes "agola.io/agola/services/runservice/types"
)

const (
	RunEventsLockKey = "runevents"
)

func (n *NotificationService) runEventsHandlerLoop(ctx context.Context) {
	for {
		if err := n.runEventsHandler(ctx); err != nil {
			n.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (n *NotificationService) runEventsHandler(ctx context.Context) error {
	l := n.lf.NewLock(RunEventsLockKey)
	if err := l.TryLock(ctx); err != nil {
		if errors.Is(err, lock.ErrLocked) {
			return nil
		}
		return errors.WithStack(err)
	}
	defer func() { _ = l.Unlock() }()

	var afterSequence uint64
	err := n.d.Do(ctx, func(tx *sql.Tx) error {
		lastRunEventSequence, err := n.d.GetLastRunEventSequence(tx)
		if err != nil {
			return errors.WithStack(err)
		}
		if lastRunEventSequence != nil {
			afterSequence = lastRunEventSequence.Value
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	resp, err := n.runserviceClient.GetRunEvents(ctx, afterSequence)
	if err != nil {
		return errors.WithStack(err)
	}
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("http status code: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	br := bufio.NewReader(resp.Body)
	stop := false

	var buf bytes.Buffer
	for {
		if stop {
			return nil
		}
		line, err := br.ReadBytes('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return errors.WithStack(err)
			}
			if len(line) == 0 {
				return nil
			}
			stop = true
		}
		switch {
		case bytes.HasPrefix(line, []byte("data: ")):
			buf.Write(line[6:])
		case bytes.Equal(line, []byte("\n")):
			data := buf.Bytes()
			buf.Reset()

			var ev *rstypes.RunEvent
			if err := json.Unmarshal(data, &ev); err != nil {
				return errors.WithStack(err)
			}

			var webhookPayload []byte
			var commitStatus *commitStatus

			// Currently we're handling only events of type runphasechanged.
			switch ev.RunEventType {
			case rstypes.RunPhaseChanged:
				commitStatus, err = n.generateCommitStatus(ctx, ev)
				if err != nil {
					n.log.Error().Msgf("failed to generate commit status")
				}
				if n.c.WebhookURL != "" {
					runWebhook := n.generatewebhook(ctx, ev)
					webhookPayload, err = json.Marshal(runWebhook)
					if err != nil {
						n.log.Error().Msgf("failed to unmarshal run webhook")
					}
				}
			default:
				n.log.Error().Msgf("run event %q is not valid", ev.RunEventType)
			}

			err = n.d.Do(ctx, func(tx *sql.Tx) error {
				lastRunEventSequence, err := n.d.GetLastRunEventSequence(tx)
				if err != nil {
					return errors.WithStack(err)
				}
				if lastRunEventSequence != nil {
					if ev.Sequence <= lastRunEventSequence.Value {
						n.log.Error().Msgf("runEvent sequence %d already processed", ev.Sequence)
						return nil
					}
				}

				if commitStatus != nil {
					cs := types.NewCommitStatus(tx)
					cs.ProjectID = commitStatus.ProjectID
					cs.State = commitStatus.State
					cs.RunCounter = commitStatus.RunCounter
					cs.CommitSHA = commitStatus.CommitSHA
					cs.Description = commitStatus.Description
					cs.Context = commitStatus.Context

					if err := n.d.InsertCommitStatus(tx, cs); err != nil {
						return errors.WithStack(err)
					}

					commitStatusDelivery := types.NewCommitStatusDelivery(tx)
					commitStatusDelivery.CommitStatusID = cs.ID
					commitStatusDelivery.DeliveryStatus = types.DeliveryStatusNotDelivered

					if err := n.d.InsertCommitStatusDelivery(tx, commitStatusDelivery); err != nil {
						return errors.WithStack(err)
					}
				}

				if webhookPayload != nil {
					data := ev.Data.(*rstypes.RunEventData)

					wh := types.NewRunWebhook(tx)
					wh.Payload = webhookPayload
					wh.ProjectID = data.Annotations[action.AnnotationProjectID]

					if err := n.d.InsertRunWebhook(tx, wh); err != nil {
						return errors.WithStack(err)
					}

					runWebhookDelivery := types.NewRunWebhookDelivery(tx)
					runWebhookDelivery.RunWebhookID = wh.ID
					runWebhookDelivery.DeliveryStatus = types.DeliveryStatusNotDelivered

					if err := n.d.InsertRunWebhookDelivery(tx, runWebhookDelivery); err != nil {
						return errors.WithStack(err)
					}
				}

				if lastRunEventSequence == nil {
					lastRunEventSequence = types.NewLastRunEventSequence(tx)
				}
				lastRunEventSequence.Value = ev.Sequence

				if err := n.d.InsertOrUpdateLastRunEventSequence(tx, lastRunEventSequence); err != nil {
					return errors.WithStack(err)
				}

				return nil
			})
			if err != nil {
				return errors.WithStack(err)
			}
		default:
			return errors.Errorf("wrong data")
		}
	}
}
