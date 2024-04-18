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

	"agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"
)

type RemoteSourceHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewRemoteSourceHandler(log zerolog.Logger, ah *action.ActionHandler) *RemoteSourceHandler {
	return &RemoteSourceHandler{log: log, ah: ah}
}

func (h *RemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *RemoteSourceHandler) do(r *http.Request) (*types.RemoteSource, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	rsRef := vars["remotesourceref"]

	remoteSource, err := h.ah.GetRemoteSource(ctx, rsRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return remoteSource, nil
}

type CreateRemoteSourceHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateRemoteSourceHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateRemoteSourceHandler {
	return &CreateRemoteSourceHandler{log: log, ah: ah}
}

func (h *CreateRemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *CreateRemoteSourceHandler) do(r *http.Request) (*types.RemoteSource, error) {
	ctx := r.Context()

	var req *csapitypes.CreateUpdateRemoteSourceRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	areq := &action.CreateUpdateRemoteSourceRequest{
		Name:                req.Name,
		APIURL:              req.APIURL,
		SkipVerify:          req.SkipVerify,
		Type:                req.Type,
		AuthType:            req.AuthType,
		Oauth2ClientID:      req.Oauth2ClientID,
		Oauth2ClientSecret:  req.Oauth2ClientSecret,
		SSHHostKey:          req.SSHHostKey,
		SkipSSHHostKeyCheck: req.SkipSSHHostKeyCheck,
		RegistrationEnabled: req.RegistrationEnabled,
		LoginEnabled:        req.LoginEnabled,
	}

	remoteSource, err := h.ah.CreateRemoteSource(ctx, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return remoteSource, nil
}

type UpdateRemoteSourceHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUpdateRemoteSourceHandler(log zerolog.Logger, ah *action.ActionHandler) *UpdateRemoteSourceHandler {
	return &UpdateRemoteSourceHandler{log: log, ah: ah}
}

func (h *UpdateRemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UpdateRemoteSourceHandler) do(r *http.Request) (*types.RemoteSource, error) {
	ctx := r.Context()

	vars := mux.Vars(r)
	rsRef := vars["remotesourceref"]

	var req *csapitypes.CreateUpdateRemoteSourceRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	areq := &action.CreateUpdateRemoteSourceRequest{
		Name:                req.Name,
		APIURL:              req.APIURL,
		SkipVerify:          req.SkipVerify,
		Type:                req.Type,
		AuthType:            req.AuthType,
		Oauth2ClientID:      req.Oauth2ClientID,
		Oauth2ClientSecret:  req.Oauth2ClientSecret,
		SSHHostKey:          req.SSHHostKey,
		SkipSSHHostKeyCheck: req.SkipSSHHostKeyCheck,
		RegistrationEnabled: req.RegistrationEnabled,
		LoginEnabled:        req.LoginEnabled,
	}

	remoteSource, err := h.ah.UpdateRemoteSource(ctx, rsRef, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return remoteSource, nil
}

type DeleteRemoteSourceHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteRemoteSourceHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteRemoteSourceHandler {
	return &DeleteRemoteSourceHandler{log: log, ah: ah}
}

func (h *DeleteRemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *DeleteRemoteSourceHandler) do(r *http.Request) error {
	ctx := r.Context()

	vars := mux.Vars(r)
	rsRef := vars["remotesourceref"]

	err := h.ah.DeleteRemoteSource(ctx, rsRef)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
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

func (h *RemoteSourcesHandler) do(w http.ResponseWriter, r *http.Request) ([]*types.RemoteSource, error) {
	ctx := r.Context()
	query := r.URL.Query()

	ropts, err := parseRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	startRemoteSourceName := query.Get("startremotesourcename")

	ares, err := h.ah.GetRemoteSources(ctx, &action.GetRemoteSourcesRequest{StartRemoteSourceName: startRemoteSourceName, Limit: ropts.Limit, SortDirection: ropts.SortDirection})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	addHasMoreHeader(w, ares.HasMore)

	return ares.RemoteSources, nil
}

type LinkedAccountsHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewLinkedAccountsHandler(log zerolog.Logger, ah *action.ActionHandler) *LinkedAccountsHandler {
	return &LinkedAccountsHandler{log: log, ah: ah}
}

func (h *LinkedAccountsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *LinkedAccountsHandler) do(r *http.Request) ([]*types.LinkedAccount, error) {
	ctx := r.Context()
	query := r.URL.Query()

	queryType := query.Get("query_type")

	remoteUserID := query.Get("remoteuserid")
	remoteSourceID := query.Get("remotesourceid")

	linkedAccounts, err := h.ah.GetLinkedAccounts(ctx, &action.GetLinkedAccountsRequest{QueryType: queryType, RemoteUserID: remoteUserID, RemoteSourceID: remoteSourceID})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return linkedAccounts, nil
}
