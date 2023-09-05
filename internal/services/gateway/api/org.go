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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/gateway/action"
	"agola.io/agola/internal/services/gateway/common"
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

type UpdateOrgHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUpdateOrgHandler(log zerolog.Logger, ah *action.ActionHandler) *UpdateOrgHandler {
	return &UpdateOrgHandler{log: log, ah: ah}
}

func (h *UpdateOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	var req gwapitypes.UpdateOrgRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
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
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createOrgResponse(org)
	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
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

type OrgsCursor struct {
	LastOrgID string
	Asc       bool
}

const (
	DefaultOrgsLimit = 10
	MaxOrgsLimit     = 20
)

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

	cursorS := query.Get("cursor")
	var start string
	var asc bool

	if cursorS != "" {
		decodedCursor, err := base64.StdEncoding.DecodeString(cursorS)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot decode cursor")))
			return
		}

		var cursor OrgsCursor
		if err := json.Unmarshal(decodedCursor, &cursor); err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot unmarshal cursor")))
			return
		}

		asc = cursor.Asc

		org, err := h.ah.GetOrg(ctx, cursor.LastOrgID)
		if util.HTTPError(w, err) {
			h.log.Err(err).Send()
			return
		}
		if org == nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cursor not valid")))
			return
		}
		start = org.Name
	} else {
		if _, ok := query["asc"]; ok {
			asc = true
		}

		start = query.Get("start")
	}

	limit := DefaultOrgsLimit
	limitS := query.Get("limit")
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
	if limit > MaxOrgsLimit {
		limit = MaxOrgsLimit
	}

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

	cursorS = ""
	if csorgs.HasMoreData {
		cursor := OrgsCursor{
			LastOrgID: csorgs.Orgs[limit-1].ID,
			Asc:       asc,
		}
		serializedCursor, err := json.Marshal(&cursor)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrInternal, errors.Wrapf(err, "cannot marshal cursor")))
			return
		}
		cursorS = base64.StdEncoding.EncodeToString(serializedCursor)
	}

	orgs := make([]*gwapitypes.OrgResponse, len(csorgs.Orgs))
	for i, p := range csorgs.Orgs {
		orgs[i] = createOrgResponse(p)
	}
	response := &gwapitypes.OrgsResponse{
		Orgs:   orgs,
		Cursor: cursorS,
	}
	if err := util.HTTPResponse(w, http.StatusOK, response); err != nil {
		h.log.Err(err).Send()
	}
}

func createOrgMemberResponse(user *cstypes.User, role cstypes.MemberRole) *gwapitypes.OrgMemberResponse {
	return &gwapitypes.OrgMemberResponse{
		User: createUserResponse(user),
		Role: gwapitypes.MemberRole(role),
	}
}

type OrgMembersCursor struct {
	LastOrgUserID string
	Asc           bool
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
	query := r.URL.Query()

	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	cursorS := query.Get("cursor")
	var asc bool
	var start string

	if cursorS != "" {
		decodedCursor, err := base64.StdEncoding.DecodeString(cursorS)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot decode cursor")))
			return
		}

		var cursor OrgMembersCursor
		if err := json.Unmarshal(decodedCursor, &cursor); err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cannot unmarshal cursor")))
			return
		}

		user, err := h.ah.GetUser(ctx, cursor.LastOrgUserID)
		if util.HTTPError(w, err) {
			h.log.Err(err).Send()
			return
		}
		if user == nil {
			util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "cursor not valid")))
			return
		}
		asc = cursor.Asc
		start = user.Name
	} else {
		if _, ok := query["asc"]; ok {
			asc = true
		}

		start = query.Get("start")
	}

	var limit int
	limitS := query.Get("limit")
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

	ares, err := h.ah.GetOrgMembers(ctx, orgRef, start, limit, asc)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	cursorS = ""
	if ares.HasMoreData {
		cursor := OrgMembersCursor{
			LastOrgUserID: ares.Members[limit-1].User.ID,
			Asc:           asc,
		}
		serializedCursor, err := json.Marshal(&cursor)
		if err != nil {
			util.HTTPError(w, util.NewAPIError(util.ErrInternal, errors.Wrapf(err, "cannot marshal cursor")))
			return
		}
		cursorS = base64.StdEncoding.EncodeToString(serializedCursor)
	}

	res := &gwapitypes.OrgMembersResponse{
		Organization: createOrgResponse(ares.Organization),
		OrgMembers:   make([]*gwapitypes.OrgMemberResponse, len(ares.Members)),
		Cursor:       cursorS,
	}
	for i, m := range ares.Members {
		res.OrgMembers[i] = createOrgMemberResponse(m.User, m.Role)
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

type CreateOrgInvitationHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateOrgInvitationHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateOrgInvitationHandler {
	return &CreateOrgInvitationHandler{log: log, ah: ah}
}

func (h *CreateOrgInvitationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	var req gwapitypes.CreateOrgInvitationRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	creq := &action.CreateOrgInvitationRequest{
		UserRef:         req.UserRef,
		OrganizationRef: orgRef,
		Role:            req.Role,
	}

	cOrgInvitation, err := h.ah.CreateOrgInvitation(ctx, creq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := createOrgInvitationResponse(cOrgInvitation.OrgInvitation, cOrgInvitation.Organization)
	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

type OrgInvitationsHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewOrgInvitationsHandler(log zerolog.Logger, ah *action.ActionHandler) *OrgInvitationsHandler {
	return &OrgInvitationsHandler{log: log, ah: ah}
}

func (h *OrgInvitationsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	query := r.URL.Query()

	orgRef := vars["orgref"]

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
	if limit > MaxOrgInvitationsLimit {
		limit = MaxOrgInvitationsLimit
	}

	orgInvitations, err := h.ah.GetOrgInvitations(ctx, orgRef, limit)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, orgInvitations); err != nil {
		h.log.Err(err).Send()
	}
}

type OrgInvitationHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewOrgInvitationHandler(log zerolog.Logger, ah *action.ActionHandler) *OrgInvitationHandler {
	return &OrgInvitationHandler{log: log, ah: ah}
}

func (h *OrgInvitationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]
	userRef := vars["userref"]

	orgInvitation, err := h.ah.GetOrgInvitation(ctx, orgRef, userRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	resp := createOrgInvitationResponse(orgInvitation.OrgInvitation, orgInvitation.Organization)
	if err := util.HTTPResponse(w, http.StatusOK, resp); err != nil {
		h.log.Err(err).Send()
	}
}

type UserOrgInvitationActionHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUserOrgInvitationActionHandler(log zerolog.Logger, ah *action.ActionHandler) *UserOrgInvitationActionHandler {
	return &UserOrgInvitationActionHandler{log: log, ah: ah}
}

func (h *UserOrgInvitationActionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	var req gwapitypes.OrgInvitationActionRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	areq := &action.OrgInvitationActionRequest{
		OrgRef: orgRef,
		Action: req.Action,
	}
	err := h.ah.OrgInvitationAction(ctx, areq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, nil); err != nil {
		h.log.Err(err).Send()
	}
}

type DeleteOrgInvitationHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteOrgInvitationHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteOrgInvitationHandler {
	return &DeleteOrgInvitationHandler{log: log, ah: ah}
}

func (h *DeleteOrgInvitationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]
	userRef := vars["userref"]

	err := h.ah.DeleteOrgInvitation(ctx, orgRef, userRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
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
