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

package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/util"
	cstypes "agola.io/agola/services/configstore/types"
	gwapitypes "agola.io/agola/services/gateway/api/types"
)

type CreateRemoteSourceHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateRemoteSourceHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateRemoteSourceHandler {
	return &CreateRemoteSourceHandler{log: log, ah: ah}
}

func (h *CreateRemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req gwapitypes.CreateRemoteSourceRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	creq := &action.CreateRemoteSourceRequest{
		Name:                req.Name,
		APIURL:              req.APIURL,
		Type:                req.Type,
		AuthType:            req.AuthType,
		SkipVerify:          req.SkipVerify,
		Oauth2ClientID:      req.Oauth2ClientID,
		Oauth2ClientSecret:  req.Oauth2ClientSecret,
		SSHHostKey:          req.SSHHostKey,
		SkipSSHHostKeyCheck: req.SkipSSHHostKeyCheck,
		RegistrationEnabled: req.RegistrationEnabled,
		LoginEnabled:        req.LoginEnabled,
	}
	rs, err := h.ah.CreateRemoteSource(ctx, creq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createRemoteSourceResponse(rs)
	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

type UpdateRemoteSourceHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUpdateRemoteSourceHandler(log zerolog.Logger, ah *action.ActionHandler) *UpdateRemoteSourceHandler {
	return &UpdateRemoteSourceHandler{log: log, ah: ah}
}

func (h *UpdateRemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	rsRef := vars["remotesourceref"]

	var req gwapitypes.UpdateRemoteSourceRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	creq := &action.UpdateRemoteSourceRequest{
		RemoteSourceRef: rsRef,

		Name:                req.Name,
		APIURL:              req.APIURL,
		SkipVerify:          req.SkipVerify,
		Oauth2ClientID:      req.Oauth2ClientID,
		Oauth2ClientSecret:  req.Oauth2ClientSecret,
		SSHHostKey:          req.SSHHostKey,
		SkipSSHHostKeyCheck: req.SkipSSHHostKeyCheck,
		RegistrationEnabled: req.RegistrationEnabled,
		LoginEnabled:        req.LoginEnabled,
	}
	rs, err := h.ah.UpdateRemoteSource(ctx, creq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createRemoteSourceResponse(rs)
	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func createRemoteSourceResponse(r *cstypes.RemoteSource) *gwapitypes.RemoteSourceResponse {
	rs := &gwapitypes.RemoteSourceResponse{
		ID:                  r.ID,
		Name:                r.Name,
		AuthType:            string(r.AuthType),
		RegistrationEnabled: r.RegistrationEnabled,
		LoginEnabled:        r.LoginEnabled,
	}
	return rs
}

type RemoteSourceHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewRemoteSourceHandler(log zerolog.Logger, ah *action.ActionHandler) *RemoteSourceHandler {
	return &RemoteSourceHandler{log: log, ah: ah}
}

func (h *RemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	rsRef := vars["remotesourceref"]

	rs, err := h.ah.GetRemoteSource(ctx, rsRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createRemoteSourceResponse(rs)
	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

type RemoteSourcesHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewRemoteSourcesHandler(log zerolog.Logger, ah *action.ActionHandler) *RemoteSourcesHandler {
	return &RemoteSourcesHandler{log: log, ah: ah}
}

func (h *RemoteSourcesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *RemoteSourcesHandler) do(w http.ResponseWriter, r *http.Request) ([]*gwapitypes.RemoteSourceResponse, error) {
	ctx := r.Context()

	ropts, err := parseRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	ares, err := h.ah.GetRemoteSources(ctx, &action.GetRemoteSourcesRequest{Cursor: ropts.Cursor, Limit: ropts.Limit, SortDirection: action.SortDirection(ropts.SortDirection)})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	remoteSources := make([]*gwapitypes.RemoteSourceResponse, len(ares.RemoteSources))
	for i, rs := range ares.RemoteSources {
		remoteSources[i] = createRemoteSourceResponse(rs)
	}

	addCursorHeader(w, ares.Cursor)

	return remoteSources, nil
}

type DeleteRemoteSourceHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteRemoteSourceHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteRemoteSourceHandler {
	return &DeleteRemoteSourceHandler{log: log, ah: ah}
}

func (h *DeleteRemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	rsRef := vars["remotesourceref"]

	err := h.ah.DeleteRemoteSource(ctx, rsRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}
