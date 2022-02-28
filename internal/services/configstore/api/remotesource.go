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

	"agola.io/agola/internal/db"
	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/services/configstore/readdb"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

type RemoteSourceHandler struct {
	log    zerolog.Logger
	readDB *readdb.ReadDB
}

func NewRemoteSourceHandler(log zerolog.Logger, readDB *readdb.ReadDB) *RemoteSourceHandler {
	return &RemoteSourceHandler{log: log, readDB: readDB}
}

func (h *RemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	rsRef := vars["remotesourceref"]

	var remoteSource *types.RemoteSource
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		remoteSource, err = h.readDB.GetRemoteSource(tx, rsRef)
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

	var req types.RemoteSource
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	remoteSource, err := h.ah.CreateRemoteSource(ctx, &req)
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

	var remoteSource *types.RemoteSource
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&remoteSource); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.UpdateRemoteSourceRequest{
		RemoteSourceRef: rsRef,
		RemoteSource:    remoteSource,
	}
	remoteSource, err := h.ah.UpdateRemoteSource(ctx, areq)
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
	log    zerolog.Logger
	readDB *readdb.ReadDB
}

func NewRemoteSourcesHandler(log zerolog.Logger, readDB *readdb.ReadDB) *RemoteSourcesHandler {
	return &RemoteSourcesHandler{log: log, readDB: readDB}
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

	remoteSources, err := h.readDB.GetRemoteSources(ctx, start, limit, asc)
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, remoteSources); err != nil {
		h.log.Err(err).Send()
	}
}
