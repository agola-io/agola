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

type OrgHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewOrgHandler(logger *zap.Logger, readDB *readdb.ReadDB) *OrgHandler {
	return &OrgHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *OrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	var org *types.Organization
	err := h.readDB.Do(func(tx *db.Tx) error {
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
		httpError(w, util.NewErrNotFound(errors.Errorf("org %q doesn't exist", orgRef)))
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
	h.log.Infof("deleteorghandler")
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

type AddOrgMemberRequest struct {
	Role types.MemberRole
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

	var req AddOrgMemberRequest
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

type OrgMemberResponse struct {
	User *types.User
	Role types.MemberRole
}

func orgMemberResponse(orgUser *action.OrgMemberResponse) *OrgMemberResponse {
	return &OrgMemberResponse{
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

	res := make([]*OrgMemberResponse, len(orgUsers))
	for i, orgUser := range orgUsers {
		res[i] = orgMemberResponse(orgUser)
	}

	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
