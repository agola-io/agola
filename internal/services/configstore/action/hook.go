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
	"net/url"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/sql"

	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"
)

func (h *ActionHandler) GetHook(ctx context.Context, hookID string) (*types.Hook, error) {
	var hook *types.Hook
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		hook, err = h.d.GetHook(tx, hookID)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return hook, nil
}

func (h *ActionHandler) GetProjectHooks(ctx context.Context, projectRef string) ([]*types.Hook, error) {
	var hooks []*types.Hook
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		p, err := h.d.GetProject(tx, projectRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if p == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with ref %q not exists", projectRef))
		}

		hooks, err = h.d.GetHooks(tx, p.ID)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return hooks, nil
}

func (h *ActionHandler) ValidateCreateHookReq(ctx context.Context, req *CreateHookRequest) error {
	if req.ProjectRef == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project ref required"))
	}
	if req.DestinationURL == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("destination url required"))
	}
	if _, err := url.ParseRequestURI(req.DestinationURL); err != nil {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid destination url %q", req.DestinationURL))
	}
	if req.ContentType == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("content type required"))
	}
	if !req.ErrorEvent && !req.FailedEvent && !req.SuccessEvent && !req.PendingEvent {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("no events defined"))
	}

	return nil
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
	if err := h.ValidateCreateHookReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var hook *types.Hook
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		// check project exists
		p, err := h.d.GetProject(tx, req.ProjectRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if p == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with ref %q not exists", req.ProjectRef))
		}

		hook = types.NewHook()
		hook.ContentType = req.ContentType
		hook.DestinationURL = req.DestinationURL
		hook.Secret = req.Secret
		hook.ProjectID = p.ID
		hook.SuccessEvent = &req.SuccessEvent
		hook.ErrorEvent = &req.ErrorEvent
		hook.PendingEvent = &req.PendingEvent
		hook.FailedEvent = &req.FailedEvent

		if err := h.d.InsertHook(tx, hook); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return hook, errors.WithStack(err)
}

func (h *ActionHandler) ValidateUpdateHookReq(ctx context.Context, req *UpdateHookRequest) error {
	if req.DestinationURL == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("destination url required"))
	}
	if _, err := url.ParseRequestURI(req.DestinationURL); err != nil {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid destination url %q", req.DestinationURL))
	}
	if req.ContentType == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("content type required"))
	}
	if !req.ErrorEvent && !req.FailedEvent && !req.SuccessEvent && !req.PendingEvent {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("no events defined"))
	}

	return nil
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
	if err := h.ValidateUpdateHookReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var hook *types.Hook
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		// check hook exists
		hook, err := h.d.GetHook(tx, curHookID)
		if err != nil {
			return errors.WithStack(err)
		}
		if hook == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("hook with id %q doesn't exists", curHookID))
		}

		// update current variable
		hook.DestinationURL = req.DestinationURL
		hook.ContentType = req.ContentType
		hook.Secret = req.Secret
		hook.SuccessEvent = &req.SuccessEvent
		hook.PendingEvent = &req.PendingEvent
		hook.ErrorEvent = &req.ErrorEvent
		hook.FailedEvent = &req.FailedEvent

		if err := h.d.UpdateHook(tx, hook); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return hook, errors.WithStack(err)
}

func (h *ActionHandler) DeleteHook(ctx context.Context, curHookID string) error {
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		// check hook exists
		hook, err := h.d.GetHook(tx, curHookID)
		if err != nil {
			return errors.WithStack(err)
		}
		if hook == nil {
			return util.NewAPIError(util.ErrNotExist, errors.Errorf("hook with id %q doesn't exists", curHookID))
		}

		if err := h.d.DeleteHook(tx, hook.ID); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(err)
}
