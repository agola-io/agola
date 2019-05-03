// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package action

import (
	"context"
	"net/http"

	rsapi "github.com/sorintlab/agola/internal/services/runservice/scheduler/api"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
)

func (h *ActionHandler) GetRun(ctx context.Context, runID string) (*rsapi.RunResponse, error) {
	runResp, resp, err := h.runserviceClient.GetRun(ctx, runID)
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
	runResp, resp, err := h.runserviceClient.GetRun(ctx, req.RunID)
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

func (h *ActionHandler) RunAction(ctx context.Context, req *RunActionsRequest) error {
	runResp, resp, err := h.runserviceClient.GetRun(ctx, req.RunID)
	if err != nil {
		return ErrFromRemote(resp, err)
	}
	canGetRun, err := h.CanDoRunActions(ctx, runResp.RunConfig.Group)
	if err != nil {
		return errors.Wrapf(err, "failed to determine permissions")
	}
	if !canGetRun {
		return util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	switch req.ActionType {
	case RunActionTypeRestart:
		rsreq := &rsapi.RunCreateRequest{
			RunID:     req.RunID,
			FromStart: req.FromStart,
		}

		resp, err := h.runserviceClient.CreateRun(ctx, rsreq)
		if err != nil {
			return ErrFromRemote(resp, err)
		}

	case RunActionTypeStop:
		rsreq := &rsapi.RunActionsRequest{
			ActionType: rsapi.RunActionTypeStop,
		}

		resp, err := h.runserviceClient.RunActions(ctx, req.RunID, rsreq)
		if err != nil {
			return ErrFromRemote(resp, err)
		}

	default:
		return util.NewErrBadRequest(errors.Errorf("wrong run action type %q", req.ActionType))
	}

	return nil
}

type RunTaskActionType string

const (
	RunTaskActionTypeApprove RunTaskActionType = "approve"
)

type RunTaskActionsRequest struct {
	RunID  string
	TaskID string

	ActionType          RunTaskActionType
	ApprovalAnnotations map[string]string
}

func (h *ActionHandler) RunTaskAction(ctx context.Context, req *RunTaskActionsRequest) error {
	runResp, resp, err := h.runserviceClient.GetRun(ctx, req.RunID)
	if err != nil {
		return ErrFromRemote(resp, err)
	}
	canGetRun, err := h.CanDoRunActions(ctx, runResp.RunConfig.Group)
	if err != nil {
		return errors.Wrapf(err, "failed to determine permissions")
	}
	if !canGetRun {
		return util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	switch req.ActionType {
	case RunTaskActionTypeApprove:
		rsreq := &rsapi.RunTaskActionsRequest{
			ActionType:          rsapi.RunTaskActionTypeApprove,
			ApprovalAnnotations: req.ApprovalAnnotations,
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
