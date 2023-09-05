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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"

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

type RemoteSourcesCursor struct {
	LastRemoteSourceID string
	Asc                bool
}

const (
	DefaultRemoteSourcesLimit = 25
	MaxRemoteSourcesLimit     = 40
)

type RemoteSourcesHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewRemoteSourcesHandler(log zerolog.Logger, ah *action.ActionHandler) *RemoteSourcesHandler {
	return &RemoteSourcesHandler{log: log, ah: ah}
}

func (h *RemoteSourcesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()

	cursorS := query.Get("cursor")
	var start string
	var asc bool

	if cursorS != "" {
		decodedCursor, err := base64.StdEncoding.DecodeString(cursorS)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot decode cursor")))
			return
		}

		var cursor RemoteSourcesCursor
		if err := json.Unmarshal(decodedCursor, &cursor); err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot unmarshal cursor")))
			return
		}

		remoteSource, err := h.ah.GetRemoteSource(ctx, cursor.LastRemoteSourceID)
		if util.HTTPError(w, err) {
			h.log.Err(err).Send()
			return
		}
		if remoteSource == nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cursor not valid")))
			return
		}
		start = remoteSource.Name
		asc = cursor.Asc
	} else {
		if _, ok := query["asc"]; ok {
			asc = true
		}
		start = query.Get("start")
	}

	limit := DefaultRemoteSourcesLimit
	limitS := query.Get("limit")
	if limitS != "" {
		var err error
		limit, err = strconv.Atoi(limitS)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot parse limit")))
			return
		}
	}
	if limit < 0 {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Errorf("limit must be greater or equal than 0")))
		return
	}
	if limit > MaxRemoteSourcesLimit {
		limit = MaxRemoteSourcesLimit
	}

	areq := &action.GetRemoteSourcesRequest{
		Start: start,
		Limit: limit,
		Asc:   asc,
	}
	csRemoteSources, err := h.ah.GetRemoteSources(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	cursorS = ""
	if csRemoteSources.HasMoreData {
		cursor := RemoteSourcesCursor{
			LastRemoteSourceID: csRemoteSources.RemoteSources[limit-1].ID,
			Asc:                asc,
		}
		serializedCursor, err := json.Marshal(&cursor)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrInternal, errors.Wrapf(err, "cannot marshal cursor")))
			return
		}
		cursorS = base64.StdEncoding.EncodeToString(serializedCursor)
	}

	remoteSources := make([]*gwapitypes.RemoteSourceResponse, len(csRemoteSources.RemoteSources))
	for i, rs := range csRemoteSources.RemoteSources {
		remoteSources[i] = createRemoteSourceResponse(rs)
	}

	response := &gwapitypes.RemoteSourcesResponse{
		RemoteSources: remoteSources,
		Cursor:        cursorS,
	}
	if err := util.HTTPResponse(w, http.StatusOK, response); err != nil {
		h.log.Err(err).Send()
	}
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
