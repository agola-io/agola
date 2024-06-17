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

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	serrors "agola.io/agola/internal/services/errors"
	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/util"
	cstypes "agola.io/agola/services/configstore/types"
	gwapitypes "agola.io/agola/services/gateway/api/types"
)

type CreateOrgHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateOrgHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateOrgHandler {
	return &CreateOrgHandler{log: log, ah: ah}
}

func (h *CreateOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *CreateOrgHandler) do(r *http.Request) (*gwapitypes.OrgResponse, error) {
	ctx := r.Context()

	var req gwapitypes.CreateOrgRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	creq := &action.CreateOrgRequest{
		Name:       req.Name,
		Visibility: cstypes.Visibility(req.Visibility),
	}

	org, err := h.ah.CreateOrg(ctx, creq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createOrgResponse(org)

	return res, nil
}

type UpdateOrgHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUpdateOrgHandler(log zerolog.Logger, ah *action.ActionHandler) *UpdateOrgHandler {
	return &UpdateOrgHandler{log: log, ah: ah}
}

func (h *UpdateOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UpdateOrgHandler) do(r *http.Request) (*gwapitypes.OrgResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	var req gwapitypes.UpdateOrgRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	var visibility *cstypes.Visibility
	if req.Visibility != nil {
		v := cstypes.Visibility(*req.Visibility)
		visibility = &v
	}
	creq := &action.UpdateOrgRequest{
		Visibility: visibility,
	}

	org, err := h.ah.UpdateOrg(ctx, orgRef, creq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createOrgResponse(org)

	return res, nil
}

type DeleteOrgHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteOrgHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteOrgHandler {
	return &DeleteOrgHandler{log: log, ah: ah}
}

func (h *DeleteOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *DeleteOrgHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	err := h.ah.DeleteOrg(ctx, orgRef)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type OrgHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewOrgHandler(log zerolog.Logger, ah *action.ActionHandler) *OrgHandler {
	return &OrgHandler{log: log, ah: ah}
}

func (h *OrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *OrgHandler) do(r *http.Request) (*gwapitypes.OrgResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	org, err := h.ah.GetOrg(ctx, orgRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createOrgResponse(org)

	return res, nil
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
	res, err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *OrgsHandler) do(w http.ResponseWriter, r *http.Request) ([]*gwapitypes.OrgResponse, error) {
	ctx := r.Context()

	ropts, err := parseRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	ares, err := h.ah.GetOrgs(ctx, &action.GetOrgsRequest{Cursor: ropts.Cursor, Limit: ropts.Limit, SortDirection: action.SortDirection(ropts.SortDirection)})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	orgs := make([]*gwapitypes.OrgResponse, len(ares.Orgs))
	for i, p := range ares.Orgs {
		orgs[i] = createOrgResponse(p)
	}

	addCursorHeader(w, ares.Cursor)

	return orgs, nil
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
	res, err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *OrgMembersHandler) do(w http.ResponseWriter, r *http.Request) (*gwapitypes.OrgMembersResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	ropts, err := parseRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	ares, err := h.ah.GetOrgMembers(ctx, &action.GetOrgMembersRequest{OrgRef: orgRef, Cursor: ropts.Cursor, Limit: ropts.Limit, SortDirection: action.SortDirection(ropts.SortDirection)})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := &gwapitypes.OrgMembersResponse{
		Organization: createOrgResponse(ares.Organization),
		Members:      make([]*gwapitypes.OrgMemberResponse, len(ares.Members)),
	}
	for i, m := range ares.Members {
		res.Members[i] = createOrgMemberResponse(m.User, m.Role)
	}

	addCursorHeader(w, ares.Cursor)

	return res, nil
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
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *AddOrgMemberHandler) do(r *http.Request) (*gwapitypes.AddOrgMemberResponse, error) {
	ctx := r.Context()

	vars := mux.Vars(r)
	orgRef := vars["orgref"]
	userRef := vars["userref"]

	var req gwapitypes.AddOrgMemberRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	ares, err := h.ah.AddOrgMember(ctx, orgRef, userRef, cstypes.MemberRole(req.Role))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createAddOrgMemberResponse(ares.Org, ares.User, ares.OrganizationMember.MemberRole)

	return res, nil
}

type RemoveOrgMemberHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewRemoveOrgMemberHandler(log zerolog.Logger, ah *action.ActionHandler) *RemoveOrgMemberHandler {
	return &RemoveOrgMemberHandler{log: log, ah: ah}
}

func (h *RemoveOrgMemberHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *RemoveOrgMemberHandler) do(r *http.Request) error {
	ctx := r.Context()

	vars := mux.Vars(r)
	orgRef := vars["orgref"]
	userRef := vars["userref"]

	err := h.ah.RemoveOrgMember(ctx, orgRef, userRef)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type CreateOrgInvitationHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateOrgInvitationHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateOrgInvitationHandler {
	return &CreateOrgInvitationHandler{log: log, ah: ah}
}

func (h *CreateOrgInvitationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *CreateOrgInvitationHandler) do(r *http.Request) (*gwapitypes.OrgInvitationResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	var req gwapitypes.CreateOrgInvitationRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	creq := &action.CreateOrgInvitationRequest{
		UserRef:         req.UserRef,
		OrganizationRef: orgRef,
		Role:            req.Role,
	}

	cOrgInvitation, err := h.ah.CreateOrgInvitation(ctx, creq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createOrgInvitationResponse(cOrgInvitation.OrgInvitation, cOrgInvitation.Organization)

	return res, nil
}

type OrgInvitationsHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewOrgInvitationsHandler(log zerolog.Logger, ah *action.ActionHandler) *OrgInvitationsHandler {
	return &OrgInvitationsHandler{log: log, ah: ah}
}

func (h *OrgInvitationsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *OrgInvitationsHandler) do(r *http.Request) ([]*cstypes.OrgInvitation, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	query := r.URL.Query()

	orgRef := vars["orgref"]

	limitS := query.Get("limit")
	limit := DefaultLimit
	if limitS != "" {
		var err error
		limit, err = strconv.Atoi(limitS)
		if err != nil {
			return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err, util.WithAPIErrorMsg("cannot parse limit"), serrors.InvalidLimit())
		}
	}
	if limit < 0 {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("limit must be greater or equal than 0"), serrors.InvalidLimit())
	}
	if limit > MaxOrgInvitationsLimit {
		limit = MaxOrgInvitationsLimit
	}

	orgInvitations, err := h.ah.GetOrgInvitations(ctx, orgRef, limit)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return orgInvitations, nil
}

type OrgInvitationHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewOrgInvitationHandler(log zerolog.Logger, ah *action.ActionHandler) *OrgInvitationHandler {
	return &OrgInvitationHandler{log: log, ah: ah}
}

func (h *OrgInvitationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *OrgInvitationHandler) do(r *http.Request) (*gwapitypes.OrgInvitationResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]
	userRef := vars["userref"]

	orgInvitation, err := h.ah.GetOrgInvitation(ctx, orgRef, userRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := createOrgInvitationResponse(orgInvitation.OrgInvitation, orgInvitation.Organization)

	return res, nil
}

type UserOrgInvitationActionHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUserOrgInvitationActionHandler(log zerolog.Logger, ah *action.ActionHandler) *UserOrgInvitationActionHandler {
	return &UserOrgInvitationActionHandler{log: log, ah: ah}
}

func (h *UserOrgInvitationActionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *UserOrgInvitationActionHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	var req gwapitypes.OrgInvitationActionRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	areq := &action.OrgInvitationActionRequest{
		OrgRef: orgRef,
		Action: req.Action,
	}
	err := h.ah.OrgInvitationAction(ctx, areq)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type DeleteOrgInvitationHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteOrgInvitationHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteOrgInvitationHandler {
	return &DeleteOrgInvitationHandler{log: log, ah: ah}
}

func (h *DeleteOrgInvitationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *DeleteOrgInvitationHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]
	userRef := vars["userref"]

	err := h.ah.DeleteOrgInvitation(ctx, orgRef, userRef)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

const (
	DefaultOrgInvitationsLimit = 25
	MaxOrgInvitationsLimit     = 40
)

func createOrgInvitationResponse(orgInvitation *cstypes.OrgInvitation, org *cstypes.Organization) *gwapitypes.OrgInvitationResponse {
	return &gwapitypes.OrgInvitationResponse{
		ID:               orgInvitation.ID,
		UserID:           orgInvitation.UserID,
		OrganizationID:   org.ID,
		OrganizationName: org.Name,
	}
}
