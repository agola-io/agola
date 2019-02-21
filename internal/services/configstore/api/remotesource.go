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
	"github.com/sorintlab/agola/internal/services/configstore/command"
	"github.com/sorintlab/agola/internal/services/configstore/readdb"
	"github.com/sorintlab/agola/internal/services/types"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type GetRemoteSourceHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewGetRemoteSourceHandler(logger *zap.Logger, readDB *readdb.ReadDB) *GetRemoteSourceHandler {
	return &GetRemoteSourceHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *GetRemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	remoteSourceID := vars["id"]

	var remoteSource *types.RemoteSource
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		remoteSource, err = h.readDB.GetRemoteSource(tx, remoteSourceID)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if remoteSource == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(remoteSource); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type GetRemoteSourceByNameHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewGetRemoteSourceByNameHandler(logger *zap.Logger, readDB *readdb.ReadDB) *GetRemoteSourceByNameHandler {
	return &GetRemoteSourceByNameHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *GetRemoteSourceByNameHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	remoteSourceName := vars["name"]

	var remoteSource *types.RemoteSource
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		remoteSource, err = h.readDB.GetRemoteSourceByName(tx, remoteSourceName)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if remoteSource == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(remoteSource); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type CreateRemoteSourceHandler struct {
	log    *zap.SugaredLogger
	ch     *command.CommandHandler
	readDB *readdb.ReadDB
}

func NewCreateRemoteSourceHandler(logger *zap.Logger, ch *command.CommandHandler) *CreateRemoteSourceHandler {
	return &CreateRemoteSourceHandler{log: logger.Sugar(), ch: ch}
}

func (h *CreateRemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req types.RemoteSource
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	remoteSource, err := h.ch.CreateRemoteSource(ctx, &req)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(remoteSource); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type DeleteRemoteSourceHandler struct {
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

func NewDeleteRemoteSourceHandler(logger *zap.Logger, ch *command.CommandHandler) *DeleteRemoteSourceHandler {
	return &DeleteRemoteSourceHandler{log: logger.Sugar(), ch: ch}
}

func (h *DeleteRemoteSourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	remoteSourceName := vars["name"]

	if err := h.ch.DeleteRemoteSource(ctx, remoteSourceName); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
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
			http.Error(w, "", http.StatusBadRequest)
			return
		}
	}
	if limit < 0 {
		http.Error(w, "limit must be greater or equal than 0", http.StatusBadRequest)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(remoteSources); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
