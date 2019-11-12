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

package types

import (
	"time"

	rstypes "agola.io/agola/services/runservice/types"
)

type RunsResponse struct {
	ID          string            `json:"id"`
	Counter     uint64            `json:"counter"`
	Name        string            `json:"name"`
	Annotations map[string]string `json:"annotations"`
	Phase       rstypes.RunPhase  `json:"phase"`
	Result      rstypes.RunResult `json:"result"`

	TasksWaitingApproval []string `json:"tasks_waiting_approval"`

	EnqueueTime *time.Time `json:"enqueue_time"`
	StartTime   *time.Time `json:"start_time"`
	EndTime     *time.Time `json:"end_time"`
}

type RunResponse struct {
	ID          string            `json:"id"`
	Counter     uint64            `json:"counter"`
	Name        string            `json:"name"`
	Annotations map[string]string `json:"annotations"`
	Phase       rstypes.RunPhase  `json:"phase"`
	Result      rstypes.RunResult `json:"result"`
	SetupErrors []string          `json:"setup_errors"`
	Stopping    bool              `json:"stopping"`

	Tasks                map[string]*RunResponseTask `json:"tasks"`
	TasksWaitingApproval []string                    `json:"tasks_waiting_approval"`

	EnqueueTime *time.Time `json:"enqueue_time"`
	StartTime   *time.Time `json:"start_time"`
	EndTime     *time.Time `json:"end_time"`

	CanRestartFromScratch     bool `json:"can_restart_from_scratch"`
	CanRestartFromFailedTasks bool `json:"can_restart_from_failed_tasks"`
}

type RunResponseTask struct {
	ID      string                                  `json:"id"`
	Name    string                                  `json:"name"`
	Status  rstypes.RunTaskStatus                   `json:"status"`
	Level   int                                     `json:"level"`
	Depends map[string]*rstypes.RunConfigTaskDepend `json:"depends"`

	WaitingApproval     bool              `json:"waiting_approval"`
	Approved            bool              `json:"approved"`
	ApprovalAnnotations map[string]string `json:"approval_annotations"`

	StartTime *time.Time `json:"start_time"`
	EndTime   *time.Time `json:"end_time"`
}

type RunTaskResponse struct {
	ID     string                `json:"id"`
	Name   string                `json:"name"`
	Status rstypes.RunTaskStatus `json:"status"`

	WaitingApproval     bool              `json:"waiting_approval"`
	Approved            bool              `json:"approved"`
	ApprovalAnnotations map[string]string `json:"approval_annotations"`

	SetupStep *RunTaskResponseSetupStep `json:"setup_step"`
	Steps     []*RunTaskResponseStep    `json:"steps"`

	StartTime *time.Time `json:"start_time"`
	EndTime   *time.Time `json:"end_time"`
}

type RunTaskResponseSetupStep struct {
	Phase rstypes.ExecutorTaskPhase `json:"phase"`
	Name  string                    `json:"name"`

	StartTime *time.Time `json:"start_time"`
	EndTime   *time.Time `json:"end_time"`
}

type RunTaskResponseStep struct {
	Phase   rstypes.ExecutorTaskPhase `json:"phase"`
	Type    string                    `json:"type"`
	Name    string                    `json:"name"`
	Command string                    `json:"command"`
	Shell   string                    `json:"shell"`

	ExitStatus *int `json:"exit_status"`

	StartTime *time.Time `json:"start_time"`
	EndTime   *time.Time `json:"end_time"`

	LogArchived bool `json:"log_archived"`
}

type RunActionType string

const (
	RunActionTypeRestart RunActionType = "restart"
	RunActionTypeCancel  RunActionType = "cancel"
	RunActionTypeStop    RunActionType = "stop"
)

type RunActionsRequest struct {
	ActionType RunActionType `json:"action_type"`

	// Restart
	FromStart bool `json:"from_start"`
}

type RunTaskActionType string

const (
	RunTaskActionTypeApprove RunTaskActionType = "approve"
)

type RunTaskActionsRequest struct {
	ActionType RunTaskActionType `json:"action_type"`
}
