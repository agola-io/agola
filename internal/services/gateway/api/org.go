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

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/util"
	cstypes "agola.io/agola/services/configstore/types"
	gwapitypes "agola.io/agola/services/gateway/api/types"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

type CreateOrgHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateOrgHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateOrgHandler {
	return &CreateOrgHandler{log: log, ah: ah}
}

func (h *CreateOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID := common.CurrentUserID(ctx)

	var req gwapitypes.CreateOrgRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	creq := &action.CreateOrgRequest{
		Name:          req.Name,
		Visibility:    cstypes.Visibility(req.Visibility),
		CreatorUserID: userID,
	}

	org, err := h.ah.CreateOrg(ctx, creq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createOrgResponse(org)
	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

type DeleteOrgHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteOrgHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteOrgHandler {
	return &DeleteOrgHandler{log: log, ah: ah}
}

func (h *DeleteOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	err := h.ah.DeleteOrg(ctx, orgRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

type OrgHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewOrgHandler(log zerolog.Logger, ah *action.ActionHandler) *OrgHandler {
	return &OrgHandler{log: log, ah: ah}
}

func (h *OrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	org, err := h.ah.GetOrg(ctx, orgRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createOrgResponse(org)
	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func createOrgResponse(o *cstypes.Organization) *gwapitypes.OrgResponse {
	org := &gwapitypes.OrgResponse{
		ID:         o.ID,
		Name:       o.Name,
		Visibility: gwapitypes.Visibility(o.Visibility),
	}
	return org
}

type OrgsHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewOrgsHandler(log zerolog.Logger, ah *action.ActionHandler) *OrgsHandler {
	return &OrgsHandler{log: log, ah: ah}
}

func (h *OrgsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()

	limitS := query.Get("limit")
	limit := DefaultRunsLimit
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
	if limit > MaxRunsLimit {
		limit = MaxRunsLimit
	}
	asc := false
	if _, ok := query["asc"]; ok {
		asc = true
	}

	start := query.Get("start")

	areq := &action.GetOrgsRequest{
		Start: start,
		Limit: limit,
		Asc:   asc,
	}
	csorgs, err := h.ah.GetOrgs(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	orgs := make([]*gwapitypes.OrgResponse, len(csorgs))
	for i, p := range csorgs {
		orgs[i] = createOrgResponse(p)
	}
	if err := util.HTTPResponse(w, http.StatusOK, orgs); err != nil {
		h.log.Err(err).Send()
	}
}

func createOrgMemberResponse(user *cstypes.User, role cstypes.MemberRole) *gwapitypes.OrgMemberResponse {
	return &gwapitypes.OrgMemberResponse{
		User: createUserResponse(user),
		Role: gwapitypes.MemberRole(role),
	}
}

type OrgMembersHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewOrgMembersHandler(log zerolog.Logger, ah *action.ActionHandler) *OrgMembersHandler {
	return &OrgMembersHandler{log: log, ah: ah}
}

func (h *OrgMembersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	ares, err := h.ah.GetOrgMembers(ctx, orgRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := &gwapitypes.OrgMembersResponse{
		Organization: createOrgResponse(ares.Organization),
		Members:      make([]*gwapitypes.OrgMemberResponse, len(ares.Members)),
	}
	for i, m := range ares.Members {
		res.Members[i] = createOrgMemberResponse(m.User, m.Role)
	}
	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func createAddOrgMemberResponse(org *cstypes.Organization, user *cstypes.User, role cstypes.MemberRole) *gwapitypes.AddOrgMemberResponse {
	return &gwapitypes.AddOrgMemberResponse{
		Organization: createOrgResponse(org),
		OrgMemberResponse: gwapitypes.OrgMemberResponse{
			User: createUserResponse(user),
			Role: gwapitypes.MemberRole(role),
		},
	}
}

type AddOrgMemberHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewAddOrgMemberHandler(log zerolog.Logger, ah *action.ActionHandler) *AddOrgMemberHandler {
	return &AddOrgMemberHandler{log: log, ah: ah}
}

func (h *AddOrgMemberHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	orgRef := vars["orgref"]
	userRef := vars["userref"]

	var req gwapitypes.AddOrgMemberRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	ares, err := h.ah.AddOrgMember(ctx, orgRef, userRef, cstypes.MemberRole(req.Role))
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createAddOrgMemberResponse(ares.Org, ares.User, ares.OrganizationMember.MemberRole)
	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

type RemoveOrgMemberHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewRemoveOrgMemberHandler(log zerolog.Logger, ah *action.ActionHandler) *RemoveOrgMemberHandler {
	return &RemoveOrgMemberHandler{log: log, ah: ah}
}

func (h *RemoveOrgMemberHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	orgRef := vars["orgref"]
	userRef := vars["userref"]

	err := h.ah.RemoveOrgMember(ctx, orgRef, userRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}
