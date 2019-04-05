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

type OrgHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewOrgHandler(logger *zap.Logger, readDB *readdb.ReadDB) *OrgHandler {
	return &OrgHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *OrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID := vars["orgid"]

	var org *types.Organization
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		org, err = h.readDB.GetOrg(tx, orgID)
		return err
	})
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if org == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(org); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

type OrgByNameHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewOrgByNameHandler(logger *zap.Logger, readDB *readdb.ReadDB) *OrgByNameHandler {
	return &OrgByNameHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *OrgByNameHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgName := vars["orgname"]

	var org *types.Organization
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		org, err = h.readDB.GetOrgByName(tx, orgName)
		return err
	})
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if org == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(org); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

type CreateOrgHandler struct {
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

func NewCreateOrgHandler(logger *zap.Logger, ch *command.CommandHandler) *CreateOrgHandler {
	return &CreateOrgHandler{log: logger.Sugar(), ch: ch}
}

func (h *CreateOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req types.Organization
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	org, err := h.ch.CreateOrg(ctx, &req)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := json.NewEncoder(w).Encode(org); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

type DeleteOrgHandler struct {
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

func NewDeleteOrgHandler(logger *zap.Logger, ch *command.CommandHandler) *DeleteOrgHandler {
	return &DeleteOrgHandler{log: logger.Sugar(), ch: ch}
}

func (h *DeleteOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.log.Infof("deleteorghandler")
	ctx := r.Context()

	vars := mux.Vars(r)
	orgName := vars["orgname"]

	err := h.ch.DeleteOrg(ctx, orgName)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
	}
}

const (
	DefaultOrgsLimit = 10
	MaxOrgsLimit     = 20
)

type OrgsHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewOrgsHandler(logger *zap.Logger, readDB *readdb.ReadDB) *OrgsHandler {
	return &OrgsHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *OrgsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	limitS := query.Get("limit")
	limit := DefaultOrgsLimit
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
	if limit > MaxOrgsLimit {
		limit = MaxOrgsLimit
	}
	asc := false
	if _, ok := query["asc"]; ok {
		asc = true
	}

	start := query.Get("start")

	var orgs []*types.Organization
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		orgs, err = h.readDB.GetOrgs(tx, start, limit, asc)
		return err
	})
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if err := json.NewEncoder(w).Encode(orgs); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}
