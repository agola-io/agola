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
	"agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/services/configstore/readdb"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	errors "golang.org/x/xerrors"
)

type OrgHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewOrgHandler(logger *zap.Logger, readDB *readdb.ReadDB) *OrgHandler {
	return &OrgHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *OrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	var org *types.Organization
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		org, err = h.readDB.GetOrg(tx, orgRef)
		return err
	})
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if org == nil {
		httpError(w, util.NewErrNotExist(errors.Errorf("org %q doesn't exist", orgRef)))
		return
	}

	if err := httpResponse(w, http.StatusOK, org); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type CreateOrgHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewCreateOrgHandler(logger *zap.Logger, ah *action.ActionHandler) *CreateOrgHandler {
	return &CreateOrgHandler{log: logger.Sugar(), ah: ah}
}

func (h *CreateOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req types.Organization
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	org, err := h.ah.CreateOrg(ctx, &req)
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
	ah  *action.ActionHandler
}

func NewDeleteOrgHandler(logger *zap.Logger, ah *action.ActionHandler) *DeleteOrgHandler {
	return &DeleteOrgHandler{log: logger.Sugar(), ah: ah}
}

func (h *DeleteOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	err := h.ah.DeleteOrg(ctx, orgRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
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
	ctx := r.Context()
	query := r.URL.Query()

	limitS := query.Get("limit")
	limit := DefaultOrgsLimit
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
	if limit > MaxOrgsLimit {
		limit = MaxOrgsLimit
	}
	asc := false
	if _, ok := query["asc"]; ok {
		asc = true
	}

	start := query.Get("start")

	var orgs []*types.Organization
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
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

type AddOrgMemberHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewAddOrgMemberHandler(logger *zap.Logger, ah *action.ActionHandler) *AddOrgMemberHandler {
	return &AddOrgMemberHandler{log: logger.Sugar(), ah: ah}
}

func (h *AddOrgMemberHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	orgRef := vars["orgref"]
	userRef := vars["userref"]

	var req csapitypes.AddOrgMemberRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	org, err := h.ah.AddOrgMember(ctx, orgRef, userRef, req.Role)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, org); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type RemoveOrgMemberHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewRemoveOrgMemberHandler(logger *zap.Logger, ah *action.ActionHandler) *RemoveOrgMemberHandler {
	return &RemoveOrgMemberHandler{log: logger.Sugar(), ah: ah}
}

func (h *RemoveOrgMemberHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	orgRef := vars["orgref"]
	userRef := vars["userref"]

	err := h.ah.RemoveOrgMember(ctx, orgRef, userRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

func orgMemberResponse(orgUser *action.OrgMemberResponse) *csapitypes.OrgMemberResponse {
	return &csapitypes.OrgMemberResponse{
		User: orgUser.User,
		Role: orgUser.Role,
	}
}

type OrgMembersHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewOrgMembersHandler(logger *zap.Logger, ah *action.ActionHandler) *OrgMembersHandler {
	return &OrgMembersHandler{log: logger.Sugar(), ah: ah}
}

func (h *OrgMembersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	orgUsers, err := h.ah.GetOrgMembers(ctx, orgRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := make([]*csapitypes.OrgMemberResponse, len(orgUsers))
	for i, orgUser := range orgUsers {
		res[i] = orgMemberResponse(orgUser)
	}

	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
