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

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/configstore/command"
	"github.com/sorintlab/agola/internal/services/configstore/readdb"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

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
		httpError(w, util.NewErrNotFound(errors.Errorf("org %q doesn't exist", orgID)))
		return
	}

	if err := httpResponse(w, http.StatusOK, org); err != nil {
		h.log.Errorf("err: %+v", err)
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
		httpError(w, util.NewErrNotFound(errors.Errorf("org %q doesn't exist", orgName)))
		return
	}

	if err := httpResponse(w, http.StatusOK, org); err != nil {
		h.log.Errorf("err: %+v", err)
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
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	org, err := h.ch.CreateOrg(ctx, &req)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, org); err != nil {
		h.log.Errorf("err: %+v", err)
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
	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
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
			httpError(w, util.NewErrBadRequest(errors.Wrapf(err, "cannot parse limit")))
			return
		}
	}
	if limit < 0 {
		httpError(w, util.NewErrBadRequest(errors.Errorf("limit must be greater or equal than 0")))
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

	if err := httpResponse(w, http.StatusOK, orgs); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
