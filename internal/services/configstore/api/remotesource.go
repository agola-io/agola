// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/configstore/action"
	"github.com/sorintlab/agola/internal/services/configstore/readdb"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	errors "golang.org/x/xerrors"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type RemoteSourceHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewRemoteSourceHandler(logger *zap.Logger, readDB *readdb.ReadDB) *RemoteSourceHandler {
	return &RemoteSourceHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *RemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	rsRef := vars["remotesourceref"]

	var remoteSource *types.RemoteSource
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		remoteSource, err = h.readDB.GetRemoteSource(tx, rsRef)
		return err
	})
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if remoteSource == nil {
		httpError(w, util.NewErrNotFound(errors.Errorf("remote source %q doesn't exist", rsRef)))
		return
	}

	if err := httpResponse(w, http.StatusOK, remoteSource); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type CreateRemoteSourceHandler struct {
	log    *zap.SugaredLogger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewCreateRemoteSourceHandler(logger *zap.Logger, ah *action.ActionHandler) *CreateRemoteSourceHandler {
	return &CreateRemoteSourceHandler{log: logger.Sugar(), ah: ah}
}

func (h *CreateRemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req types.RemoteSource
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	remoteSource, err := h.ah.CreateRemoteSource(ctx, &req)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, remoteSource); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type UpdateRemoteSourceHandler struct {
	log    *zap.SugaredLogger
	ah     *action.ActionHandler
	readDB *readdb.ReadDB
}

func NewUpdateRemoteSourceHandler(logger *zap.Logger, ah *action.ActionHandler) *UpdateRemoteSourceHandler {
	return &UpdateRemoteSourceHandler{log: logger.Sugar(), ah: ah}
}

func (h *UpdateRemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	rsRef := vars["remotesourceref"]

	var remoteSource *types.RemoteSource
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&remoteSource); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	areq := &action.UpdateRemoteSourceRequest{
		RemoteSourceRef: rsRef,
		RemoteSource:    remoteSource,
	}
	remoteSource, err := h.ah.UpdateRemoteSource(ctx, areq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, remoteSource); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type DeleteRemoteSourceHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewDeleteRemoteSourceHandler(logger *zap.Logger, ah *action.ActionHandler) *DeleteRemoteSourceHandler {
	return &DeleteRemoteSourceHandler{log: logger.Sugar(), ah: ah}
}

func (h *DeleteRemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	rsRef := vars["remotesourceref"]

	err := h.ah.DeleteRemoteSource(ctx, rsRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
	}
	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

const (
	DefaultRemoteSourcesLimit = 10
	MaxRemoteSourcesLimit     = 20
)

type RemoteSourcesHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewRemoteSourcesHandler(logger *zap.Logger, readDB *readdb.ReadDB) *RemoteSourcesHandler {
	return &RemoteSourcesHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *RemoteSourcesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	limitS := query.Get("limit")
	limit := DefaultRemoteSourcesLimit
	if limitS != "" {
		var err error
		limit, err = strconv.Atoi(limitS)
		if err != nil {
			httpError(w, util.NewErrBadRequest(errors.Errorf("cannot parse limit: %w", err)))
			return
		}
	}
	if limit < 0 {
		httpError(w, util.NewErrBadRequest(errors.Errorf("limit must be greater or equal than 0")))
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

	remoteSources, err := h.readDB.GetRemoteSources(start, limit, asc)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if err := httpResponse(w, http.StatusOK, remoteSources); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
