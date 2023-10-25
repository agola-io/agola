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

package types

import "time"

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
