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

	action "agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"
)

type UserHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUserHandler(log zerolog.Logger, ah *action.ActionHandler) *UserHandler {
	return &UserHandler{log: log, ah: ah}
}

func (h *UserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UserHandler) do(r *http.Request) (*types.User, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	user, err := h.ah.GetUser(ctx, userRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return user, nil
}

type CreateUserHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateUserHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateUserHandler {
	return &CreateUserHandler{log: log, ah: ah}
}

func (h *CreateUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *CreateUserHandler) do(r *http.Request) (*types.User, error) {
	ctx := r.Context()

	var req *csapitypes.CreateUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	creq := &action.CreateUserRequest{
		UserName: req.UserName,
	}
	if req.CreateUserLARequest != nil {
		creq.CreateUserLARequest = &action.CreateUserLARequest{
			RemoteSourceName:           req.CreateUserLARequest.RemoteSourceName,
			RemoteUserID:               req.CreateUserLARequest.RemoteUserID,
			RemoteUserName:             req.CreateUserLARequest.RemoteUserName,
			UserAccessToken:            req.CreateUserLARequest.UserAccessToken,
			Oauth2AccessToken:          req.CreateUserLARequest.Oauth2AccessToken,
			Oauth2RefreshToken:         req.CreateUserLARequest.Oauth2RefreshToken,
			Oauth2AccessTokenExpiresAt: req.CreateUserLARequest.Oauth2AccessTokenExpiresAt,
		}
	}

	user, err := h.ah.CreateUser(ctx, creq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return user, nil
}

type UpdateUserHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUpdateUserHandler(log zerolog.Logger, ah *action.ActionHandler) *UpdateUserHandler {
	return &UpdateUserHandler{log: log, ah: ah}
}

func (h *UpdateUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UpdateUserHandler) do(r *http.Request) (*types.User, error) {
	ctx := r.Context()

	vars := mux.Vars(r)
	userRef := vars["userref"]

	var req *csapitypes.UpdateUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	creq := &action.UpdateUserRequest{
		UserRef:  userRef,
		UserName: req.UserName,
	}

	user, err := h.ah.UpdateUser(ctx, creq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return user, nil
}

type DeleteUserHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteUserHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteUserHandler {
	return &DeleteUserHandler{log: log, ah: ah}
}

func (h *DeleteUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *DeleteUserHandler) do(r *http.Request) error {
	ctx := r.Context()

	vars := mux.Vars(r)
	userRef := vars["userref"]

	if err := h.ah.DeleteUser(ctx, userRef); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type UsersHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUsersHandler(log zerolog.Logger, ah *action.ActionHandler) *UsersHandler {
	return &UsersHandler{log: log, ah: ah}
}

func (h *UsersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UsersHandler) do(w http.ResponseWriter, r *http.Request) ([]*types.User, error) {
	ctx := r.Context()
	query := r.URL.Query()

	ropts, err := parseRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	startUserName := query.Get("startusername")

	// handle special queries, like get user by token
	queryType := query.Get("query_type")

	if queryType != "" {
		req := &action.UserQueryRequest{
			QueryType: queryType,

			Token: query.Get("token"),

			LinkedAccountID: query.Get("linkedaccountid"),

			RemoteUserID:   query.Get("remoteuserid"),
			RemoteSourceID: query.Get("remotesourceid"),
		}

		user, err := h.ah.UserQuery(ctx, req)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		return []*types.User{user}, nil
	}

	// default query
	ares, err := h.ah.GetUsers(ctx, &action.GetUsersRequest{StartUserName: startUserName, Limit: ropts.Limit, SortDirection: ropts.SortDirection})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	users := ares.Users

	addHasMoreHeader(w, ares.HasMore)

	return users, nil
}

type UserLinkedAccountsHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUserLinkedAccountsHandler(log zerolog.Logger, ah *action.ActionHandler) *UserLinkedAccountsHandler {
	return &UserLinkedAccountsHandler{log: log, ah: ah}
}

func (h *UserLinkedAccountsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UserLinkedAccountsHandler) do(r *http.Request) ([]*types.LinkedAccount, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	linkedAccounts, err := h.ah.GetUserLinkedAccounts(ctx, userRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return linkedAccounts, nil
}

type CreateUserLAHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateUserLAHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateUserLAHandler {
	return &CreateUserLAHandler{log: log, ah: ah}
}

func (h *CreateUserLAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *CreateUserLAHandler) do(r *http.Request) (*types.LinkedAccount, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	var req csapitypes.CreateUserLARequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	creq := &action.CreateUserLARequest{
		UserRef:                    userRef,
		RemoteSourceName:           req.RemoteSourceName,
		RemoteUserID:               req.RemoteUserID,
		RemoteUserName:             req.RemoteUserName,
		UserAccessToken:            req.UserAccessToken,
		Oauth2AccessToken:          req.Oauth2AccessToken,
		Oauth2RefreshToken:         req.Oauth2RefreshToken,
		Oauth2AccessTokenExpiresAt: req.Oauth2AccessTokenExpiresAt,
	}
	linkedAccount, err := h.ah.CreateUserLA(ctx, creq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return linkedAccount, nil
}

type DeleteUserLAHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteUserLAHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteUserLAHandler {
	return &DeleteUserLAHandler{log: log, ah: ah}
}

func (h *DeleteUserLAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *DeleteUserLAHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]
	laID := vars["laid"]

	if err := h.ah.DeleteUserLA(ctx, userRef, laID); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

type UpdateUserLAHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUpdateUserLAHandler(log zerolog.Logger, ah *action.ActionHandler) *UpdateUserLAHandler {
	return &UpdateUserLAHandler{log: log, ah: ah}
}

func (h *UpdateUserLAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UpdateUserLAHandler) do(r *http.Request) (*types.LinkedAccount, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]
	linkedAccountID := vars["laid"]

	var req csapitypes.UpdateUserLARequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	creq := &action.UpdateUserLARequest{
		UserRef:                    userRef,
		LinkedAccountID:            linkedAccountID,
		RemoteUserID:               req.RemoteUserID,
		RemoteUserName:             req.RemoteUserName,
		UserAccessToken:            req.UserAccessToken,
		Oauth2AccessToken:          req.Oauth2AccessToken,
		Oauth2RefreshToken:         req.Oauth2RefreshToken,
		Oauth2AccessTokenExpiresAt: req.Oauth2AccessTokenExpiresAt,
	}
	linkedAccount, err := h.ah.UpdateUserLA(ctx, creq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return linkedAccount, nil
}

type UserTokensHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUserTokensHandler(log zerolog.Logger, ah *action.ActionHandler) *UserTokensHandler {
	return &UserTokensHandler{log: log, ah: ah}
}

func (h *UserTokensHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UserTokensHandler) do(r *http.Request) ([]*types.UserToken, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	userTokens, err := h.ah.GetUserTokens(ctx, userRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return userTokens, nil
}

type CreateUserTokenHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateUserTokenHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateUserTokenHandler {
	return &CreateUserTokenHandler{log: log, ah: ah}
}

func (h *CreateUserTokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *CreateUserTokenHandler) do(r *http.Request) (*csapitypes.CreateUserTokenResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	var req csapitypes.CreateUserTokenRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		return nil, util.NewAPIErrorWrap(util.ErrBadRequest, err)
	}

	token, err := h.ah.CreateUserToken(ctx, userRef, req.TokenName)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := &csapitypes.CreateUserTokenResponse{
		Name:  token.Name,
		Token: token.Value,
	}

	return res, nil
}

type DeleteUserTokenHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteUserTokenHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteUserTokenHandler {
	return &DeleteUserTokenHandler{log: log, ah: ah}
}

func (h *DeleteUserTokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *DeleteUserTokenHandler) do(r *http.Request) error {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]
	tokenName := vars["tokenname"]

	if err := h.ah.DeleteUserToken(ctx, userRef, tokenName); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func userOrgResponse(userOrg *action.UserOrg) *csapitypes.UserOrgResponse {
	return &csapitypes.UserOrgResponse{
		Organization: userOrg.Organization,
		Role:         userOrg.Role,
	}
}

type UserOrgHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUserOrgHandler(log zerolog.Logger, ah *action.ActionHandler) *UserOrgHandler {
	return &UserOrgHandler{log: log, ah: ah}
}

func (h *UserOrgHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UserOrgHandler) do(r *http.Request) (*csapitypes.UserOrgResponse, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]
	orgRef := vars["orgref"]

	userOrg, err := h.ah.GetUserOrg(ctx, userRef, orgRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return userOrgResponse(userOrg), nil
}

type UserOrgsHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUserOrgsHandler(log zerolog.Logger, ah *action.ActionHandler) *UserOrgsHandler {
	return &UserOrgsHandler{log: log, ah: ah}
}

func (h *UserOrgsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UserOrgsHandler) do(w http.ResponseWriter, r *http.Request) ([]*csapitypes.UserOrgResponse, error) {
	ctx := r.Context()
	query := r.URL.Query()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	ropts, err := parseRequestOptions(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	startOrgName := query.Get("startorgname")

	areq := &action.GetUserOrgsRequest{
		UserRef:      userRef,
		StartOrgName: startOrgName,

		Limit:         ropts.Limit,
		SortDirection: ropts.SortDirection,
	}
	ares, err := h.ah.GetUserOrgs(ctx, areq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	res := make([]*csapitypes.UserOrgResponse, len(ares.UserOrgs))
	for i, userOrg := range ares.UserOrgs {
		res[i] = userOrgResponse(userOrg)
	}

	addHasMoreHeader(w, ares.HasMore)

	return res, nil
}

type UserOrgInvitationsHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUserOrgInvitationsHandler(log zerolog.Logger, ah *action.ActionHandler) *UserOrgInvitationsHandler {
	return &UserOrgInvitationsHandler{log: log, ah: ah}
}

func (h *UserOrgInvitationsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.do(r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UserOrgInvitationsHandler) do(r *http.Request) ([]*types.OrgInvitation, error) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	userOrgInvitations, err := h.ah.GetUserOrgInvitations(ctx, userRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return userOrgInvitations, nil
}
