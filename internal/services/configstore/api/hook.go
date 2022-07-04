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

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
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

	var req *csapitypes.CreateHookRequest
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
		PendingEvent:   *req.PendingEvent,
		SuccessEvent:   *req.SuccessEvent,
		ErrorEvent:     *req.ErrorEvent,
		FailedEvent:    *req.FailedEvent,
	}

	hook, err := h.ah.CreateHook(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, hook); err != nil {
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

	if hook == nil {
		util.HTTPError(w, util.NewAPIError(util.ErrNotExist, errors.Errorf("hook %q doesn't exist", hookID)))
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, hook); err != nil {
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

	var req *csapitypes.UpdateHookRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.UpdateHookRequest{
		DestinationURL: req.DestinationURL,
		ContentType:    req.ContentType,
		Secret:         req.Secret,
		PendingEvent:   *req.PendingEvent,
		SuccessEvent:   *req.SuccessEvent,
		ErrorEvent:     *req.ErrorEvent,
		FailedEvent:    *req.FailedEvent,
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

	if err := util.HTTPResponse(w, http.StatusCreated, hook); err != nil {
		h.log.Err(err).Send()
	}
}
