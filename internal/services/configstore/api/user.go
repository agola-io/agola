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
	"agola.io/agola/internal/services/configstore/db"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"
)

type UserHandler struct {
	log zerolog.Logger
	d   *db.DB
}

func NewUserHandler(log zerolog.Logger, d *db.DB) *UserHandler {
	return &UserHandler{log: log, d: d}
}

func (h *UserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	var user *types.User
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		user, err = h.d.GetUser(tx, userRef)
		return errors.WithStack(err)
	})
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}

	if user == nil {
		util.HTTPError(w, util.NewAPIError(util.ErrNotExist, errors.Errorf("user %q doesn't exist", userRef)))
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, user); err != nil {
		h.log.Err(err).Send()
	}
}

type CreateUserHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateUserHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateUserHandler {
	return &CreateUserHandler{log: log, ah: ah}
}

func (h *CreateUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req *csapitypes.CreateUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
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
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, user); err != nil {
		h.log.Err(err).Send()
	}
}

type UpdateUserHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUpdateUserHandler(log zerolog.Logger, ah *action.ActionHandler) *UpdateUserHandler {
	return &UpdateUserHandler{log: log, ah: ah}
}

func (h *UpdateUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	userRef := vars["userref"]

	var req *csapitypes.UpdateUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	creq := &action.UpdateUserRequest{
		UserRef:  userRef,
		UserName: req.UserName,
	}

	user, err := h.ah.UpdateUser(ctx, creq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, user); err != nil {
		h.log.Err(err).Send()
	}
}

type DeleteUserHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteUserHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteUserHandler {
	return &DeleteUserHandler{log: log, ah: ah}
}

func (h *DeleteUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	userRef := vars["userref"]

	err := h.ah.DeleteUser(ctx, userRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
	}
	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

type UsersHandler struct {
	log zerolog.Logger
	d   *db.DB
	ah  *action.ActionHandler
}

func NewUsersHandler(log zerolog.Logger, d *db.DB, ah *action.ActionHandler) *UsersHandler {
	return &UsersHandler{log: log, d: d, ah: ah}
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

	var users []*types.User
	switch queryType {
	case "bytoken":
		err = h.d.Do(ctx, func(tx *sql.Tx) error {
			token := query.Get("token")
			user, err := h.d.GetUserByTokenValue(tx, token)
			if err != nil {
				return errors.WithStack(err)
			}
			if user == nil {
				return util.NewAPIError(util.ErrNotExist, errors.Errorf("user with required token doesn't exist"))
			}
			users = []*types.User{user}
			return nil
		})
		if err != nil {
			return nil, errors.WithStack(err)
		}

	case "bylinkedaccount":
		err = h.d.Do(ctx, func(tx *sql.Tx) error {
			linkedAccountID := query.Get("linkedaccountid")
			user, err := h.d.GetUserByLinkedAccount(tx, linkedAccountID)
			if err != nil {
				return errors.WithStack(err)
			}
			if user == nil {
				return util.NewAPIError(util.ErrNotExist, errors.Errorf("user with linked account %q token doesn't exist", linkedAccountID))
			}
			users = []*types.User{user}
			return nil
		})
		if err != nil {
			return nil, errors.WithStack(err)
		}

	case "byremoteuser":
		err = h.d.Do(ctx, func(tx *sql.Tx) error {
			remoteUserID := query.Get("remoteuserid")
			remoteSourceID := query.Get("remotesourceid")
			la, err := h.d.GetLinkedAccountByRemoteUserIDandSource(tx, remoteUserID, remoteSourceID)
			if err != nil {
				return errors.WithStack(err)
			}
			if la == nil {
				return util.NewAPIError(util.ErrNotExist, errors.Errorf("linked account with remote user %q for remote source %q token doesn't exist", remoteUserID, remoteSourceID))
			}

			user, err := h.d.GetUser(tx, la.UserID)
			if err != nil {
				return errors.WithStack(err)
			}
			if user == nil {
				return util.NewAPIError(util.ErrNotExist, errors.Errorf("user with remote user %q for remote source %q token doesn't exist", remoteUserID, remoteSourceID))
			}
			users = []*types.User{user}
			return nil
		})
		if err != nil {
			return nil, errors.WithStack(err)
		}

	default:
		// default query
		var err error

		ares, err := h.ah.GetUsers(ctx, &action.GetUsersRequest{StartUserName: startUserName, Limit: ropts.Limit, SortDirection: ropts.SortDirection})
		if err != nil {
			return nil, errors.WithStack(err)
		}

		users = ares.Users

		addHasMoreHeader(w, ares.HasMore)
	}

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
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	linkedAccounts, err := h.ah.GetUserLinkedAccounts(ctx, userRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, linkedAccounts); err != nil {
		h.log.Err(err).Send()
	}
}

type CreateUserLAHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateUserLAHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateUserLAHandler {
	return &CreateUserLAHandler{log: log, ah: ah}
}

func (h *CreateUserLAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	var req csapitypes.CreateUserLARequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
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
	user, err := h.ah.CreateUserLA(ctx, creq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, user); err != nil {
		h.log.Err(err).Send()
	}
}

type DeleteUserLAHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteUserLAHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteUserLAHandler {
	return &DeleteUserLAHandler{log: log, ah: ah}
}

func (h *DeleteUserLAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]
	laID := vars["laid"]

	err := h.ah.DeleteUserLA(ctx, userRef, laID)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
	}
	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
}

type UpdateUserLAHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUpdateUserLAHandler(log zerolog.Logger, ah *action.ActionHandler) *UpdateUserLAHandler {
	return &UpdateUserLAHandler{log: log, ah: ah}
}

func (h *UpdateUserLAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]
	linkedAccountID := vars["laid"]

	var req csapitypes.UpdateUserLARequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
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
	user, err := h.ah.UpdateUserLA(ctx, creq)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, user); err != nil {
		h.log.Err(err).Send()
	}
}

type UserTokensHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUserTokensHandler(log zerolog.Logger, ah *action.ActionHandler) *UserTokensHandler {
	return &UserTokensHandler{log: log, ah: ah}
}

func (h *UserTokensHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	linkedAccounts, err := h.ah.GetUserTokens(ctx, userRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusCreated, linkedAccounts); err != nil {
		h.log.Err(err).Send()
	}
}

type CreateUserTokenHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewCreateUserTokenHandler(log zerolog.Logger, ah *action.ActionHandler) *CreateUserTokenHandler {
	return &CreateUserTokenHandler{log: log, ah: ah}
}

func (h *CreateUserTokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	var req csapitypes.CreateUserTokenRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		util.HTTPError(w, util.NewAPIError(util.ErrBadRequest, err))
		return
	}

	token, err := h.ah.CreateUserToken(ctx, userRef, req.TokenName)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	resp := &csapitypes.CreateUserTokenResponse{
		Name:  token.Name,
		Token: token.Value,
	}
	if err := util.HTTPResponse(w, http.StatusCreated, resp); err != nil {
		h.log.Err(err).Send()
	}
}

type DeleteUserTokenHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewDeleteUserTokenHandler(log zerolog.Logger, ah *action.ActionHandler) *DeleteUserTokenHandler {
	return &DeleteUserTokenHandler{log: log, ah: ah}
}

func (h *DeleteUserTokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]
	tokenName := vars["tokenname"]

	err := h.ah.DeleteUserToken(ctx, userRef, tokenName)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}
	if err := util.HTTPResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Err(err).Send()
	}
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
	res, err := h.do(w, r)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}

func (h *UserOrgHandler) do(w http.ResponseWriter, r *http.Request) (*csapitypes.UserOrgResponse, error) {
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
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	userOrgInvitations, err := h.ah.GetUserOrgInvitations(ctx, userRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, userOrgInvitations); err != nil {
		h.log.Err(err).Send()
	}
}
