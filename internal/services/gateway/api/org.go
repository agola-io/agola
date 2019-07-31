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

	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/util"
	cstypes "agola.io/agola/services/configstore/types"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	"go.uber.org/zap"
	errors "golang.org/x/xerrors"

	"github.com/gorilla/mux"
)

type CreateOrgHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewCreateOrgHandler(logger *zap.Logger, ah *action.ActionHandler) *CreateOrgHandler {
	return &CreateOrgHandler{log: logger.Sugar(), ah: ah}
}

func (h *CreateOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var userID string
	userIDVal := ctx.Value("userid")
	if userIDVal != nil {
		userID = userIDVal.(string)
	}

	var req gwapitypes.CreateOrgRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	creq := &action.CreateOrgRequest{
		Name:          req.Name,
		Visibility:    cstypes.Visibility(req.Visibility),
		CreatorUserID: userID,
	}

	org, err := h.ah.CreateOrg(ctx, creq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createOrgResponse(org)
	if err := httpResponse(w, http.StatusCreated, res); err != nil {
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

type OrgHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewOrgHandler(logger *zap.Logger, ah *action.ActionHandler) *OrgHandler {
	return &OrgHandler{log: logger.Sugar(), ah: ah}
}

func (h *OrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	org, err := h.ah.GetOrg(ctx, orgRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createOrgResponse(org)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
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
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewOrgsHandler(logger *zap.Logger, ah *action.ActionHandler) *OrgsHandler {
	return &OrgsHandler{log: logger.Sugar(), ah: ah}
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
			httpError(w, util.NewErrBadRequest(errors.Errorf("cannot parse limit: %w", err)))
			return
		}
	}
	if limit < 0 {
		httpError(w, util.NewErrBadRequest(errors.Errorf("limit must be greater or equal than 0")))
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
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	orgs := make([]*gwapitypes.OrgResponse, len(csorgs))
	for i, p := range csorgs {
		orgs[i] = createOrgResponse(p)
	}
	if err := httpResponse(w, http.StatusOK, orgs); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

func createOrgMemberResponse(user *cstypes.User, role cstypes.MemberRole) *gwapitypes.OrgMemberResponse {
	return &gwapitypes.OrgMemberResponse{
		User: createUserResponse(user),
		Role: gwapitypes.MemberRole(role),
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

	ares, err := h.ah.GetOrgMembers(ctx, orgRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := &gwapitypes.OrgMembersResponse{
		Organization: createOrgResponse(ares.Organization),
		Members:      make([]*gwapitypes.OrgMemberResponse, len(ares.Members)),
	}
	for i, m := range ares.Members {
		res.Members[i] = createOrgMemberResponse(m.User, m.Role)
	}
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
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

	var req gwapitypes.AddOrgMemberRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	ares, err := h.ah.AddOrgMember(ctx, orgRef, userRef, cstypes.MemberRole(req.Role))
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createAddOrgMemberResponse(ares.Org, ares.User, ares.OrganizationMember.MemberRole)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
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
