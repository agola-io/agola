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
	rstypes "agola.io/agola/services/runservice/types"
)

type RunResponse struct {
	Run                     *rstypes.Run       `json:"run"`
	RunConfig               *rstypes.RunConfig `json:"run_config"`
	ChangeGroupsUpdateToken string             `json:"change_groups_update_tokens"`
}

type GetRunsResponse struct {
	Runs                    []*rstypes.Run `json:"runs"`
	ChangeGroupsUpdateToken string         `json:"change_groups_update_tokens"`
}

type RunCreateRequest struct {
	// new run fields
	RunConfigTasks    map[string]*rstypes.RunConfigTask `json:"run_config_tasks"`
	Name              string                            `json:"name"`
	Group             string                            `json:"group"`
	SetupErrors       []string                          `json:"setup_errors"`
	StaticEnvironment map[string]string                 `json:"static_environment"`
	CacheGroup        string                            `json:"cache_group"`

	// existing run fields
	RunID      string   `json:"run_id"`
	FromStart  bool     `json:"from_start"`
	ResetTasks []string `json:"reset_tasks"`

	// common fields
	Environment map[string]string `json:"environment"`
	Annotations map[string]string `json:"annotations"`

	ChangeGroupsUpdateToken string `json:"changeup_update_tokens"`
}

type RunActionType string

const (
	RunActionTypeChangePhase RunActionType = "changephase"
	RunActionTypeStop        RunActionType = "stop"
)

type RunActionsRequest struct {
	ActionType RunActionType `json:"action_type"`

	Phase                   rstypes.RunPhase `json:"phase"`
	ChangeGroupsUpdateToken string           `json:"change_groups_update_tokens"`
}

type RunTaskActionType string

const (
	RunTaskActionTypeSetAnnotations RunTaskActionType = "setannotations"
	RunTaskActionTypeApprove        RunTaskActionType = "approve"
)

type RunTaskActionsRequest struct {
	ActionType RunTaskActionType `json:"action_type"`

	// set Annotations fields
	Annotations map[string]string `json:"annotations,omitempty"`

	// global fields
	ChangeGroupsUpdateToken string `json:"change_groups_update_tokens"`
}
