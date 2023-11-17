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
	"context"
	"time"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/services/notification/types"
	"agola.io/agola/internal/sqlg/lock"
	"agola.io/agola/internal/sqlg/sql"
	nstypes "agola.io/agola/services/notification/types"
	rstypes "agola.io/agola/services/runservice/types"
)

const (
	signatureSHA256Key = "X-Agola-SHA256Signature"

	agolaEventHeader = "X-Agola-Event"

	agolaDeliveryHeader = "X-Agola-Delivery"

	webhookVersion = 1

	webhooksCleanerLockKey = "webhookscleaner"

	maxRunWebhooksQueryLimit = 40

	runWebhooksCleanerInterval = 1 * 24 * time.Hour
)

type AgolaEventType string

const (
	AgolaEventRun AgolaEventType = "run"
)

func (n *NotificationService) generatewebhook(ctx context.Context, ev *rstypes.RunEvent) *types.RunWebhook {
	data := ev.Data.(*rstypes.RunEventData)

	// ignore user direct runs
	if data.Annotations[action.AnnotationRunType] == string(common.GroupTypeUser) {
		return nil
	}

	webhook := &types.RunWebhook{
		Version: webhookVersion,
		ProjectInfo: types.ProjectInfo{
			ProjectID: data.Annotations[action.AnnotationProjectID],
		},
		Run: &types.Run{},
	}

	webhook.Run.ID = data.ID
	webhook.Run.RefType = data.Annotations[action.AnnotationRefType]
	webhook.Run.Ref = data.Annotations[action.AnnotationRef]
	webhook.Run.Name = data.Name
	webhook.Run.Counter = data.Counter
	webhook.Run.SetupErrors = data.SetupErrors
	webhook.Run.Phase = string(data.Phase)
	webhook.Run.Result = string(data.Result)
	webhook.Run.StartTime = data.StartTime
	webhook.Run.EndTime = data.EndTime
	webhook.Run.EnqueueTime = data.EnqueueTime

	webhook.Run.Tasks = make(map[string]*types.RunTask)
	for id, t := range data.Tasks {
		task := &types.RunTask{}
		task.ID = t.ID
		task.Name = data.Tasks[t.ID].Name
		task.Level = data.Tasks[t.ID].Level
		task.Depends = make(map[string]*types.RunTaskDepend)
		for tdID, td := range data.Tasks[t.ID].Depends {
			taskDepend := &types.RunTaskDepend{
				TaskID:     td.TaskID,
				Conditions: make([]string, len(td.Conditions)),
			}
			for i, c := range td.Conditions {
				taskDepend.Conditions[i] = string(c)
			}
			task.Depends[tdID] = taskDepend
		}
		task.Status = string(t.Status)
		task.Timedout = t.Timedout
		task.Skip = t.Skip
		task.WaitingApproval = t.WaitingApproval
		task.Approved = t.Approved
		task.StartTime = t.StartTime
		task.EndTime = t.EndTime
		task.SetupStep = types.RunTaskStep{
			Phase:      string(t.SetupStep.Phase),
			ExitStatus: t.SetupStep.ExitStatus,
			StartTime:  t.SetupStep.StartTime,
			EndTime:    t.SetupStep.EndTime,
		}

		steps := make([]*types.RunTaskStep, len(t.Steps))
		for i, s := range t.Steps {
			step := &types.RunTaskStep{
				Phase:      string(s.Phase),
				ExitStatus: s.ExitStatus,
				StartTime:  s.StartTime,
				EndTime:    s.EndTime,
			}
			steps[i] = step
		}
		task.Steps = steps

		webhook.Run.Tasks[id] = task
	}

	return webhook
}

func (n *NotificationService) runWebhooksCleanerLoop(ctx context.Context, runWebhookExpireInterval time.Duration) {
	n.log.Debug().Msgf("webhookCleanerLoop")

	for {
		if err := n.runWebhooksCleaner(ctx, runWebhookExpireInterval); err != nil {
			n.log.Warn().Err(err).Msgf("webhooksCleaner error")
		}

		sleepCh := time.NewTimer(runWebhooksCleanerInterval).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (n *NotificationService) runWebhooksCleaner(ctx context.Context, runWebhookExpireInterval time.Duration) error {
	l := n.lf.NewLock(webhooksCleanerLockKey)
	if err := l.TryLock(ctx); err != nil {
		if errors.Is(err, lock.ErrLocked) {
			return nil
		}
		return errors.WithStack(err)
	}
	defer func() { _ = l.Unlock() }()

	for {
		var runWebhooks []*nstypes.RunWebhook
		var afterRunWebhookID string

		err := n.d.Do(ctx, func(tx *sql.Tx) error {
			var err error
			runWebhooks, err = n.d.GetRunWebhooksAfterRunWebhookID(tx, afterRunWebhookID, maxRunWebhooksQueryLimit)
			if err != nil {
				return errors.WithStack(err)
			}

			for _, r := range runWebhooks {
				if time.Since(r.CreationTime) < runWebhookExpireInterval {
					continue
				}

				err = n.d.DeleteRunWebhookDeliveriesByRunWebhookID(tx, r.ID)
				if err != nil {
					return errors.WithStack(err)
				}

				err = n.d.DeleteRunWebhook(tx, r.ID)
				if err != nil {
					return errors.WithStack(err)
				}
			}

			return nil
		})
		if err != nil {
			return errors.WithStack(err)
		}

		if len(runWebhooks) < maxRunWebhooksQueryLimit {
			break
		}

		afterRunWebhookID = runWebhooks[len(runWebhooks)-1].ID
	}

	return nil
}
