// Copyright 2022 Sorint.lab
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

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/util"
	csatypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"
)

func (h *ActionHandler) GetProjectHooks(ctx context.Context, projectRef string) ([]*types.Hook, error) {
	hooksResp, _, err := h.configstoreClient.GetProjectHooks(ctx, projectRef)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
	}

	return hooksResp, nil
}

type CreateHookRequest struct {
	ProjectRef     string
	DestinationURL string
	ContentType    string
	Secret         string
	PendingEvent   bool
	SuccessEvent   bool
	ErrorEvent     bool
	FailedEvent    bool
}

func (h *ActionHandler) CreateHook(ctx context.Context, req *CreateHookRequest) (*types.Hook, error) {
	isProjectOwner, err := h.isUserProjectOwner(ctx, req.ProjectRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if !isProjectOwner {
		return nil, util.NewAPIError(util.ErrUnauthorized, errors.Errorf("user not owner of project %q", req.ProjectRef))
	}

	creq := csatypes.CreateHookRequest{
		ProjectRef:     req.ProjectRef,
		DestinationURL: req.DestinationURL,
		ContentType:    req.ContentType,
		Secret:         req.Secret,
		PendingEvent:   &req.PendingEvent,
		SuccessEvent:   &req.SuccessEvent,
		ErrorEvent:     &req.ErrorEvent,
		FailedEvent:    &req.FailedEvent,
	}

	hook, _, err := h.configstoreClient.CreateHook(ctx, &creq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return hook, errors.WithStack(err)
}

func (h *ActionHandler) DeleteHook(ctx context.Context, curHookID string) error {
	hook, err := h.GetHook(ctx, curHookID)
	if err != nil {
		return errors.WithStack(err)
	}
	if hook == nil {
		return util.NewAPIError(util.ErrNotExist, errors.Errorf("failed to get hook %q", curHookID))
	}

	isProjectOwner, err := h.isUserProjectOwner(ctx, hook.ProjectID)
	if err != nil {
		return errors.WithStack(err)
	}
	if !isProjectOwner {
		return util.NewAPIError(util.ErrUnauthorized, errors.Errorf("user not owner of project %q", hook.ID))
	}

	if _, err = h.configstoreClient.DeleteHook(ctx, curHookID); err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(err)
}

func (h *ActionHandler) GetHook(ctx context.Context, hookID string) (*types.Hook, error) {
	hook, _, err := h.configstoreClient.GetHook(ctx, hookID)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
	}
	return hook, nil
}

type UpdateHookRequest struct {
	DestinationURL string
	ContentType    string
	Secret         string
	PendingEvent   bool
	SuccessEvent   bool
	ErrorEvent     bool
	FailedEvent    bool
}

func (h *ActionHandler) UpdateHook(ctx context.Context, curHookID string, req *UpdateHookRequest) (*types.Hook, error) {
	creq := csatypes.UpdateHookRequest{
		DestinationURL: req.DestinationURL,
		ContentType:    req.ContentType,
		Secret:         req.Secret,
		PendingEvent:   &req.PendingEvent,
		SuccessEvent:   &req.SuccessEvent,
		ErrorEvent:     &req.ErrorEvent,
		FailedEvent:    &req.FailedEvent,
	}

	hook, err := h.GetHook(ctx, curHookID)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if hook == nil {
		return nil, util.NewAPIError(util.ErrNotExist, errors.Errorf("failed to get hook %q", curHookID))
	}

	isProjectOwner, err := h.isUserProjectOwner(ctx, hook.ProjectID)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if !isProjectOwner {
		return nil, util.NewAPIError(util.ErrUnauthorized, errors.Errorf("user not owner of project %q", hook.ProjectID))
	}

	hook, _, err = h.configstoreClient.UpdateHook(ctx, curHookID, &creq)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
	}
	return hook, nil
}

func (h *ActionHandler) isUserProjectOwner(ctx context.Context, projectRef string) (bool, error) {
	project, err := h.GetProject(ctx, projectRef)
	if err != nil {
		return false, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get project %q", projectRef))
	}
	pg, _, err := h.configstoreClient.GetProjectGroup(ctx, project.Parent.ID)
	if err != nil {
		return false, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get project group %q", project.Parent.ID))
	}
	isProjectOwner, err := h.IsProjectOwner(ctx, pg.OwnerType, project.OwnerID)
	if err != nil {
		return false, errors.Wrapf(err, "failed to determine ownership")
	}

	return isProjectOwner, nil
}
