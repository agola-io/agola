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

type CreateWebhookMessageHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateWebhookMessageHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateWebhookMessageHandler {
	return &CreateWebhookMessageHandler{log: log, ah: ah}
}

func (h *CreateWebhookMessageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req *csapitypes.CreateWebhookMessageRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.CreateWebhookMessageRequest{
		IsCustom:       req.IsCustom,
		ContentType:    req.ContentType,
		Secret:         req.Secret,
		TargetURL:      req.TargetURL,
		CommitStatus:   req.CommitStatus,
		Description:    req.Description,
		RepositoryPath: req.RepositoryPath,
		CommitSha:      req.CommitSha,
		StatusContext:  req.StatusContext,
	}
	if req.DestinationURL != nil {
		areq.DestinationURL = *req.DestinationURL
	}
	if req.ProjectID != nil {
		areq.ProjectID = *req.ProjectID
	}

	webhookMessage, err := h.ah.CreateWebhookMessage(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, webhookMessage); err != nil {
		h.log.Err(err).Send()
	}
}

type DeleteWebhookMessageHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteWebhookMessageHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteWebhookMessageHandler {
	return &DeleteWebhookMessageHandler{log: log, ah: ah}
}

func (h *DeleteWebhookMessageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	webhookmessageID, err := url.PathUnescape(vars["webhookmessageid"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	err = h.ah.DeleteWebhookMessage(ctx, webhookmessageID)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

type WebhookMessageHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewWebhookMessageHandler(log zerolog.Logger, ah *action.ActionHandler) *WebhookMessageHandler {
	return &WebhookMessageHandler{log: log, ah: ah}
}

func (h *WebhookMessageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	webhookmessageID, err := url.PathUnescape(vars["webhookmessageid"])
	if err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	webhookmessage, err := h.ah.GetWebhookMessage(ctx, webhookmessageID)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if webhookmessage == nil {
		util.HTTPError(w, util.NewAPIError(util.ErrNotExist, errors.Errorf("webhook message %q doesn't exist", webhookmessageID)))
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, webhookmessage); err != nil {
		h.log.Err(err).Send()
	}
}

type WebhookMessagesHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewWebhookMessagesHandler(log zerolog.Logger, ah *action.ActionHandler) *WebhookMessagesHandler {
	return &WebhookMessagesHandler{log: log, ah: ah}
}

func (h *WebhookMessagesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	webhookmessages, err := h.ah.GetAllWebhookMessages(ctx)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, webhookmessages); err != nil {
		h.log.Err(err).Send()
	}
}
