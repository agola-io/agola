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

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/configstore/action"
	serrors "agola.io/agola/internal/services/errors"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"
)

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

func (h *OrgHandler) do(r *http.Request) (*types.Organization, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	org, err := h.ah.GetOrg(ctx, orgRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return org, nil
}

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

func (h *CreateOrgHandler) do(r *http.Request) (*types.Organization, error) {
	ctx := r.Context()

	var req *csapitypes.CreateOrgRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	creq := &action.CreateOrgRequest{
		Name:          req.Name,
		Visibility:    req.Visibility,
		CreatorUserID: req.CreatorUserID,
	}

	org, err := h.ah.CreateOrg(ctx, creq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return org, nil
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

func (h *UpdateOrgHandler) do(r *http.Request) (*types.Organization, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	var req *csapitypes.UpdateOrgRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	creq := &action.UpdateOrgRequest{
		Visibility: req.Visibility,
	}

	org, err := h.ah.UpdateOrg(ctx, orgRef, creq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return org, nil
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

func (h *OrgsHandler) do(w http.ResponseWriter, r *http.Request) ([]*types.Organization, error) {
	ctx := r.Context()
	query := r.URL.Query()

	ropts, err := parseRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	startOrgName := query.Get("startorgname")

	var visibilities []types.Visibility
	visibilitiesStr, ok := query["visibilities"]
	if ok {
		for _, vs := range visibilitiesStr {
			if !types.IsValidVisibility(types.Visibility(vs)) {
				return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("invalid visibility"), serrors.InvalidVisibility())
			}
			visibilities = append(visibilities, types.Visibility(vs))
		}
	}

	ares, err := h.ah.GetOrgs(ctx, &action.GetOrgsRequest{StartOrgName: startOrgName, Visibilities: visibilities, Limit: ropts.Limit, SortDirection: ropts.SortDirection})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	addHasMoreHeader(w, ares.HasMore)

	return ares.Orgs, nil
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

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *AddOrgMemberHandler) do(r *http.Request) (*types.OrganizationMember, error) {
	ctx := r.Context()

	vars := mux.Vars(r)
	orgRef := vars["orgref"]
	userRef := vars["userref"]

	var req *csapitypes.AddOrgMemberRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	orgMember, err := h.ah.AddOrgMember(ctx, orgRef, userRef, req.Role)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return orgMember, nil
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

func orgMemberResponse(orgUser *action.OrgMember) *csapitypes.OrgMemberResponse {
	return &csapitypes.OrgMemberResponse{
		User: orgUser.User,
		Role: orgUser.Role,
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

func (h *OrgMembersHandler) do(w http.ResponseWriter, r *http.Request) ([]*csapitypes.OrgMemberResponse, error) {
	ctx := r.Context()
	query := r.URL.Query()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	ropts, err := parseRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	startUserName := query.Get("startusername")

	areq := &action.GetOrgMembersRequest{
		OrgRef:        orgRef,
		StartUserName: startUserName,

		Limit:         ropts.Limit,
		SortDirection: ropts.SortDirection,
	}
	ares, err := h.ah.GetOrgMembers(ctx, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := make([]*csapitypes.OrgMemberResponse, len(ares.OrgMembers))
	for i, orgMember := range ares.OrgMembers {
		res[i] = orgMemberResponse(orgMember)
	}

	addHasMoreHeader(w, ares.HasMore)

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

func (h *OrgInvitationsHandler) do(r *http.Request) ([]*types.OrgInvitation, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	orgInvitations, err := h.ah.GetOrgInvitations(ctx, orgRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return orgInvitations, nil
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

func (h *CreateOrgInvitationHandler) do(r *http.Request) (*types.OrgInvitation, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]

	var req csapitypes.CreateOrgInvitationRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	creq := &action.CreateOrgInvitationRequest{
		UserRef:         req.UserRef,
		OrganizationRef: orgRef,
		Role:            req.Role,
	}

	orgInvitation, err := h.ah.CreateOrgInvitation(ctx, creq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return orgInvitation, nil
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

func (h *OrgInvitationHandler) do(r *http.Request) (*types.OrgInvitation, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]
	userRef := vars["userref"]

	orgInvitation, err := h.ah.GetOrgInvitationByUserRef(ctx, orgRef, userRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return orgInvitation, nil
}

type OrgInvitationActionHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewOrgInvitationActionHandler(log zerolog.Logger, ah *action.ActionHandler) *OrgInvitationActionHandler {
	return &OrgInvitationActionHandler{log: log, ah: ah}
}

func (h *OrgInvitationActionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
}

func (h *OrgInvitationActionHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	orgRef := vars["orgref"]
	userRef := vars["userref"]

	var req csapitypes.OrgInvitationActionRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	creq := &action.OrgInvitationActionRequest{
		UserRef: userRef,
		OrgRef:  orgRef,
		Action:  req.Action,
	}

	err := h.ah.OrgInvitationAction(ctx, creq)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
