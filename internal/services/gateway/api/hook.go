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

package api

import (
	"encoding/json"
	"net/http"
	"net/url"

	"agola.io/agola/internal/services/gateway/action"
	util "agola.io/agola/internal/util"
	cstypes "agola.io/agola/services/configstore/types"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

type CreateHookHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateHookHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateHookHandler {
	return &CreateHookHandler{log: log, ah: ah}
}

func (h *CreateHookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req *gwapitypes.CreateHookRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.CreateHookRequest{
		ProjectRef:     req.ProjectRef,
		DestinationURL: req.DestinationURL,
		ContentType:    req.ContentType,
		Secret:         req.Secret,
	}
	if req.PendingEvent != nil {
		areq.PendingEvent = *req.PendingEvent
	}
	if req.SuccessEvent != nil {
		areq.SuccessEvent = *req.SuccessEvent
	}
	if req.ErrorEvent != nil {
		areq.ErrorEvent = *req.ErrorEvent
	}
	if req.FailedEvent != nil {
		areq.FailedEvent = *req.FailedEvent
	}

	hook, err := h.ah.CreateHook(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createHookResponse(hook)
	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

type DeleteHookHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteHookHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteHookHandler {
	return &DeleteHookHandler{log: log, ah: ah}
}

func (h *DeleteHookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	hookID, err := url.PathUnescape(vars["hookid"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	err = h.ah.DeleteHook(ctx, hookID)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

type HookHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewHookHandler(log zerolog.Logger, ah *action.ActionHandler) *HookHandler {
	return &HookHandler{log: log, ah: ah}
}

func (h *HookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	hookID, err := url.PathUnescape(vars["hookid"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	hook, err := h.ah.GetHook(ctx, hookID)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createHookResponse(hook)
	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

type UpdateHookHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUpdateHookHandler(log zerolog.Logger, ah *action.ActionHandler) *UpdateHookHandler {
	return &UpdateHookHandler{log: log, ah: ah}
}

func (h *UpdateHookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	hookID, err := url.PathUnescape(vars["hookid"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	var req *gwapitypes.UpdateHookRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.UpdateHookRequest{
		DestinationURL: req.DestinationURL,
		ContentType:    req.ContentType,
		Secret:         req.Secret,
	}
	if req.PendingEvent != nil {
		areq.PendingEvent = *req.PendingEvent
	}
	if req.SuccessEvent != nil {
		areq.SuccessEvent = *req.SuccessEvent
	}
	if req.ErrorEvent != nil {
		areq.ErrorEvent = *req.ErrorEvent
	}
	if req.FailedEvent != nil {
		areq.FailedEvent = *req.FailedEvent
	}

	hook, err := h.ah.UpdateHook(ctx, hookID, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createHookResponse(hook)
	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func createHookResponse(o *cstypes.Hook) *gwapitypes.HookResponse {
	org := &gwapitypes.HookResponse{
		ID:             o.ID,
		ProjectRef:     o.ProjectID,
		DestinationURL: o.DestinationURL,
		ContentType:    o.ContentType,
		Secret:         o.Secret,
		PendingEvent:   o.PendingEvent,
		SuccessEvent:   o.SuccessEvent,
		ErrorEvent:     o.ErrorEvent,
		FailedEvent:    o.FailedEvent,
	}
	return org
}
