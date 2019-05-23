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

	errors "golang.org/x/xerrors"
	"github.com/sorintlab/agola/internal/services/gateway/action"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	"go.uber.org/zap"

	"github.com/gorilla/mux"
)

type CreateOrgRequest struct {
	Name       string           `json:"name"`
	Visibility types.Visibility `json:"visibility"`
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

	var userID string
	userIDVal := ctx.Value("userid")
	if userIDVal != nil {
		userID = userIDVal.(string)
	}
	h.log.Infof("userID: %q", userID)

	var req CreateOrgRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	creq := &action.CreateOrgRequest{
		Name:          req.Name,
		Visibility:    req.Visibility,
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

type OrgResponse struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Visibility types.Visibility `json:"visibility,omitempty"`
}

func createOrgResponse(o *types.Organization) *OrgResponse {
	org := &OrgResponse{
		ID:         o.ID,
		Name:       o.Name,
		Visibility: o.Visibility,
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

	orgs := make([]*OrgResponse, len(csorgs))
	for i, p := range csorgs {
		orgs[i] = createOrgResponse(p)
	}
	if err := httpResponse(w, http.StatusOK, orgs); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type OrgMembersResponse struct {
	Organization *OrgResponse         `json:"organization"`
	Members      []*OrgMemberResponse `json:"members"`
}

type OrgMemberResponse struct {
	User *UserResponse    `json:"user"`
	Role types.MemberRole `json:"role"`
}

func createOrgMemberResponse(user *types.User, role types.MemberRole) *OrgMemberResponse {
	return &OrgMemberResponse{
		User: createUserResponse(user),
		Role: role,
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

	res := &OrgMembersResponse{
		Organization: createOrgResponse(ares.Organization),
		Members:      make([]*OrgMemberResponse, len(ares.Members)),
	}
	for i, m := range ares.Members {
		res.Members[i] = createOrgMemberResponse(m.User, m.Role)
	}
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type AddOrgMemberResponse struct {
	Organization *OrgResponse `json:"organization"`
	OrgMemberResponse
}

func createAddOrgMemberResponse(org *types.Organization, user *types.User, role types.MemberRole) *AddOrgMemberResponse {
	return &AddOrgMemberResponse{
		Organization: createOrgResponse(org),
		OrgMemberResponse: OrgMemberResponse{
			User: createUserResponse(user),
			Role: role,
		},
	}
}

type AddOrgMemberRequest struct {
	Role types.MemberRole `json:"role"`
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

	ares, err := h.ah.AddOrgMember(ctx, orgRef, userRef, req.Role)
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
