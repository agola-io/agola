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
	"strconv"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/services/configstore/db"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"
)

type RemoteSourceHandler struct {
	log zerolog.Logger
	d   *db.DB
}

func NewRemoteSourceHandler(log zerolog.Logger, d *db.DB) *RemoteSourceHandler {
	return &RemoteSourceHandler{log: log, d: d}
}

func (h *RemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	rsRef := vars["remotesourceref"]

	var remoteSource *types.RemoteSource
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		remoteSource, err = h.d.GetRemoteSource(tx, rsRef)
		return errors.WithStack(err)
	})
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}

	if remoteSource == nil {
		util.HTTPError(w, util.NewAPIError(util.ErrNotExist, errors.Errorf("remote source %q doesn't exist", rsRef)))
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, remoteSource); err != nil {
		h.log.Err(err).Send()
	}
}

type CreateRemoteSourceHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateRemoteSourceHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateRemoteSourceHandler {
	return &CreateRemoteSourceHandler{log: log, ah: ah}
}

func (h *CreateRemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req *csapitypes.CreateUpdateRemoteSourceRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
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
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, remoteSource); err != nil {
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

	var req *csapitypes.CreateUpdateRemoteSourceRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
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
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, remoteSource); err != nil {
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
	}
	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

const (
	DefaultRemoteSourcesLimit = 10
	MaxRemoteSourcesLimit     = 20
)

type RemoteSourcesHandler struct {
	log zerolog.Logger
	d   *db.DB
}

func NewRemoteSourcesHandler(log zerolog.Logger, d *db.DB) *RemoteSourcesHandler {
	return &RemoteSourcesHandler{log: log, d: d}
}

func (h *RemoteSourcesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()

	limitS := query.Get("limit")
	limit := DefaultRemoteSourcesLimit
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
	asc := false
	if _, ok := query["asc"]; ok {
		asc = true
	}

	start := query.Get("start")

	var hasMoreData bool
	qLimit := limit
	if qLimit != 0 {
		qLimit++
	}

	var remoteSources []*types.RemoteSource
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		remoteSources, err = h.d.GetRemoteSources(tx, start, qLimit, asc)
		return errors.WithStack(err)
	})
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}

	if limit != 0 && len(remoteSources) > limit {
		hasMoreData = true
		remoteSources = remoteSources[:limit]
	}

	response := csapitypes.RemoteSourcesReponse{
		RemoteSources: remoteSources,
		HasMoreData:   hasMoreData,
	}
	if err := util.HTTPResponse(w, http.StatusOK, response); err != nil {
		h.log.Err(err).Send()
	}
}

type LinkedAccountsHandler struct {
	log zerolog.Logger
	d   *db.DB
}

func NewLinkedAccountsHandler(log zerolog.Logger, d *db.DB) *LinkedAccountsHandler {
	return &LinkedAccountsHandler{log: log, d: d}
}

func (h *LinkedAccountsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()

	queryType := query.Get("query_type")

	var linkedAccounts []*types.LinkedAccount
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		switch queryType {
		case "byremoteuser":
			remoteUserID := query.Get("remoteuserid")
			remoteSourceID := query.Get("remotesourceid")
			la, err := h.d.GetLinkedAccountByRemoteUserIDandSource(tx, remoteUserID, remoteSourceID)
			if err != nil {
				return errors.WithStack(err)
			}
			if la == nil {
				return util.NewAPIError(util.ErrNotExist, errors.Errorf("linked account with remote user %q for remote source %q token doesn't exist", remoteUserID, remoteSourceID))
			}

			linkedAccounts = []*types.LinkedAccount{la}
		default:
			return errors.Errorf("unknown query_type: %q", queryType)
		}

		return nil
	})
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, linkedAccounts); err != nil {
		h.log.Err(err).Send()
	}
}
