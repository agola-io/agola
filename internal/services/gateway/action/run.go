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

package action

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/sorintlab/agola/internal/services/common"
	rsapi "github.com/sorintlab/agola/internal/services/runservice/api"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
)

func (h *ActionHandler) GetRun(ctx context.Context, runID string) (*rsapi.RunResponse, error) {
	runResp, resp, err := h.runserviceClient.GetRun(ctx, runID, nil)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	canGetRun, err := h.CanGetRun(ctx, runResp.RunConfig.Group)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to determine permissions")
	}
	if !canGetRun {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	return runResp, nil
}

type GetRunsRequest struct {
	PhaseFilter  []string
	Group        string
	LastRun      bool
	ChangeGroups []string
	StartRunID   string
	Limit        int
	Asc          bool
}

func (h *ActionHandler) GetRuns(ctx context.Context, req *GetRunsRequest) (*rsapi.GetRunsResponse, error) {
	canGetRun, err := h.CanGetRun(ctx, req.Group)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to determine permissions")
	}
	if !canGetRun {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	groups := []string{req.Group}
	runsResp, resp, err := h.runserviceClient.GetRuns(ctx, req.PhaseFilter, groups, req.LastRun, req.ChangeGroups, req.StartRunID, req.Limit, req.Asc)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}

	return runsResp, nil
}

type GetLogsRequest struct {
	RunID  string
	TaskID string
	Setup  bool
	Step   int
	Follow bool
	Stream bool
}

func (h *ActionHandler) GetLogs(ctx context.Context, req *GetLogsRequest) (*http.Response, error) {
	runResp, resp, err := h.runserviceClient.GetRun(ctx, req.RunID, nil)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	canGetRun, err := h.CanGetRun(ctx, runResp.RunConfig.Group)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to determine permissions")
	}
	if !canGetRun {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	resp, err = h.runserviceClient.GetLogs(ctx, req.RunID, req.TaskID, req.Setup, req.Step, req.Follow, req.Stream)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}

	return resp, nil
}

type RunActionType string

const (
	RunActionTypeRestart RunActionType = "restart"
	RunActionTypeStop    RunActionType = "stop"
)

type RunActionsRequest struct {
	RunID      string
	ActionType RunActionType

	// Restart
	FromStart bool
}

func (h *ActionHandler) RunAction(ctx context.Context, req *RunActionsRequest) (*rsapi.RunResponse, error) {
	runResp, resp, err := h.runserviceClient.GetRun(ctx, req.RunID, nil)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	canGetRun, err := h.CanDoRunActions(ctx, runResp.RunConfig.Group)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to determine permissions")
	}
	if !canGetRun {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	switch req.ActionType {
	case RunActionTypeRestart:
		rsreq := &rsapi.RunCreateRequest{
			RunID:     req.RunID,
			FromStart: req.FromStart,
		}

		runResp, resp, err = h.runserviceClient.CreateRun(ctx, rsreq)
		if err != nil {
			return nil, ErrFromRemote(resp, err)
		}

	case RunActionTypeStop:
		rsreq := &rsapi.RunActionsRequest{
			ActionType: rsapi.RunActionTypeStop,
		}

		resp, err = h.runserviceClient.RunActions(ctx, req.RunID, rsreq)
		if err != nil {
			return nil, ErrFromRemote(resp, err)
		}

	default:
		return nil, util.NewErrBadRequest(errors.Errorf("wrong run action type %q", req.ActionType))
	}

	return runResp, nil
}

type RunTaskActionType string

const (
	RunTaskActionTypeApprove RunTaskActionType = "approve"
)

type RunTaskActionsRequest struct {
	RunID  string
	TaskID string

	ActionType RunTaskActionType
}

func (h *ActionHandler) RunTaskAction(ctx context.Context, req *RunTaskActionsRequest) error {
	runResp, resp, err := h.runserviceClient.GetRun(ctx, req.RunID, nil)
	if err != nil {
		return ErrFromRemote(resp, err)
	}
	canDoRunAction, err := h.CanDoRunActions(ctx, runResp.RunConfig.Group)
	if err != nil {
		return errors.Wrapf(err, "failed to determine permissions")
	}
	if !canDoRunAction {
		return util.NewErrForbidden(errors.Errorf("user not authorized"))
	}
	curUserID := h.CurrentUserID(ctx)
	if curUserID == "" {
		return util.NewErrBadRequest(errors.Errorf("no logged in user"))
	}

	switch req.ActionType {
	case RunTaskActionTypeApprove:
		rt, ok := runResp.Run.Tasks[req.TaskID]
		if !ok {
			return util.NewErrBadRequest(errors.Errorf("run %q doesn't have task %q", req.RunID, req.TaskID))
		}

		approvers := []string{}
		annotations := map[string]string{}
		if rt.Annotations != nil {
			annotations = rt.Annotations
		}
		approversAnnotation, ok := annotations[common.ApproversAnnotation]
		if ok {
			if err := json.Unmarshal([]byte(approversAnnotation), &approvers); err != nil {
				return errors.Wrapf(err, "failed to unmarshal run task approvers annotation")
			}
		}

		for _, approver := range approvers {
			if approver == curUserID {
				return util.NewErrBadRequest(errors.Errorf("user %q alredy approved the task", approver))
			}
		}
		approvers = append(approvers, curUserID)

		approversj, err := json.Marshal(approvers)
		if err != nil {
			return errors.Wrapf(err, "failed to marshal run task approvers annotation")
		}

		annotations[common.ApproversAnnotation] = string(approversj)

		rsreq := &rsapi.RunTaskActionsRequest{
			ActionType:              rsapi.RunTaskActionTypeSetAnnotations,
			Annotations:             annotations,
			ChangeGroupsUpdateToken: runResp.ChangeGroupsUpdateToken,
		}

		resp, err := h.runserviceClient.RunTaskActions(ctx, req.RunID, req.TaskID, rsreq)
		if err != nil {
			return ErrFromRemote(resp, err)
		}

	default:
		return util.NewErrBadRequest(errors.Errorf("wrong run task action type %q", req.ActionType))
	}

	return nil
}
