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
	"io"
	"net/http"
	"time"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/gateway/action"
	rstypes "agola.io/agola/services/runservice/types"
)

const (
	signatureSHA256Key = "X-Agola-SHA256Signature"

	agolaEventHeader = "X-Agola-Event"

	webhookVersion = 1
)

type AgolaEventType string

const (
	AgolaEventRun AgolaEventType = "run"
)

type RunWebhook struct {
	// Version is the version of webhook struct data
	Version uint64 `json:"version"`

	// ProjectInfo is the info of the project
	ProjectInfo ProjectInfo `json:"project_info"`

	// Run is the current run status
	Run *Run `json:"run"`

	// TODO(alessandro.pinna) populate with action values
	//Action string `json:"action"`
}

type ProjectInfo struct {
	ProjectID string `json:"project_id"`
}

type Run struct {
	ID          string              `json:"id"`
	RefType     string              `json:"ref_type"`
	Ref         string              `json:"ref"`
	Name        string              `json:"name"`
	Counter     uint64              `json:"counter"`
	Phase       string              `json:"phase"`
	Result      string              `json:"result"`
	SetupErrors []string            `json:"setup_errors"`
	Tasks       map[string]*RunTask `json:"tasks"`
	EnqueueTime *time.Time          `json:"enqueue_time"`
	StartTime   *time.Time          `json:"start_time"`
	EndTime     *time.Time          `json:"end_time"`
}

type RunTask struct {
	ID              string                    `json:"id"`
	Name            string                    `json:"name"`
	Level           int                       `json:"level"`
	Skip            bool                      `json:"skip"`
	Depends         map[string]*RunTaskDepend `json:"depends"`
	Status          string                    `json:"status"`
	Timedout        bool                      `json:"timedout"`
	WaitingApproval bool                      `json:"waiting_approval"`
	Approved        bool                      `json:"approved"`
	SetupStep       RunTaskStep               `json:"setup_step"`
	Steps           []*RunTaskStep            `json:"steps"`
	StartTime       *time.Time                `json:"start_time"`
	EndTime         *time.Time                `json:"end_time"`
}

type RunTaskStep struct {
	Phase      string     `json:"phase"`
	ExitStatus *int       `json:"exit_status"`
	StartTime  *time.Time `json:"start_time"`
	EndTime    *time.Time `json:"end_time"`
}

type RunTaskDepend struct {
	TaskID     string   `json:"task_id"`
	Conditions []string `json:"conditions"`
}

func (n *NotificationService) sendWebhooks(ctx context.Context, ev *rstypes.RunEvent) error {
	data := ev.Data.(*rstypes.RunEventData)

	// ignore user direct runs
	if data.Annotations[action.AnnotationRunType] == string(common.GroupTypeUser) {
		return nil
	}

	webhook := &RunWebhook{
		Version: webhookVersion,
		ProjectInfo: ProjectInfo{
			ProjectID: data.Annotations[action.AnnotationProjectID],
		},
		Run: &Run{},
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

	webhook.Run.Tasks = make(map[string]*RunTask)
	for id, t := range data.Tasks {
		task := &RunTask{}
		task.ID = t.ID
		task.Name = data.Tasks[t.ID].Name
		task.Level = data.Tasks[t.ID].Level
		for tdID, td := range data.Tasks[t.ID].Depends {
			taskDepend := &RunTaskDepend{
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
		task.SetupStep = RunTaskStep{
			Phase:      string(t.SetupStep.Phase),
			ExitStatus: t.SetupStep.ExitStatus,
			StartTime:  t.SetupStep.StartTime,
			EndTime:    t.SetupStep.EndTime,
		}

		steps := make([]*RunTaskStep, len(t.Steps))
		for i, s := range t.Steps {
			step := &RunTaskStep{
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

	if err := n.sendRunWebhook(ctx, webhook); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (n *NotificationService) sendRunWebhook(ctx context.Context, webhook *RunWebhook) error {
	c := &http.Client{}

	body, err := json.Marshal(webhook)
	if err != nil {
		return errors.WithStack(err)
	}

	req, err := http.NewRequest("POST", n.c.WebhookURL, bytes.NewReader(body))
	req = req.WithContext(ctx)
	if err != nil {
		return errors.WithStack(err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add(agolaEventHeader, string(AgolaEventRun))

	if n.c.WebhookSecret != "" {
		sig256 := hmac.New(sha256.New, []byte(n.c.WebhookSecret))
		_, err = io.MultiWriter(sig256).Write([]byte(body))
		if err != nil {
			return errors.WithStack(err)
		}

		signatureSHA256 := hex.EncodeToString(sig256.Sum(nil))

		req.Header.Set(signatureSHA256Key, signatureSHA256)
	}

	_, err = c.Do(req)
	return errors.WithStack(err)
}
