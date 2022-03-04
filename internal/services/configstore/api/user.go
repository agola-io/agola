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
	action "agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/services/configstore/db"
	"agola.io/agola/internal/sql"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
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

const (
	DefaultUsersLimit = 10
	MaxUsersLimit     = 20
)

type UsersHandler struct {
	log zerolog.Logger
	d   *db.DB
}

func NewUsersHandler(log zerolog.Logger, d *db.DB) *UsersHandler {
	return &UsersHandler{log: log, d: d}
}

func (h *UsersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()

	limitS := query.Get("limit")
	limit := DefaultUsersLimit
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
	if limit > MaxUsersLimit {
		limit = MaxUsersLimit
	}
	asc := false
	if _, ok := query["asc"]; ok {
		asc = true
	}

	start := query.Get("start")

	// handle special queries, like get user by token
	queryType := query.Get("query_type")

	var users []*types.User
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		switch queryType {
		case "bytoken":
			token := query.Get("token")
			user, err := h.d.GetUserByTokenValue(tx, token)
			if err != nil {
				return errors.WithStack(err)
			}
			if user == nil {
				return util.NewAPIError(util.ErrNotExist, errors.Errorf("user with required token doesn't exist"))
			}
			users = []*types.User{user}
		case "bylinkedaccount":
			linkedAccountID := query.Get("linkedaccountid")
			user, err := h.d.GetUserByLinkedAccount(tx, linkedAccountID)
			if err != nil {
				return errors.WithStack(err)
			}
			if user == nil {
				return util.NewAPIError(util.ErrNotExist, errors.Errorf("user with linked account %q token doesn't exist", linkedAccountID))
			}
			users = []*types.User{user}
		case "byremoteuser":
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
		default:
			// default query
			var err error
			users, err = h.d.GetUsers(tx, start, limit, asc)
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		h.log.Err(err).Send()
		util.HTTPError(w, err)
		return
	}

	if err := util.HTTPResponse(w, http.StatusOK, users); err != nil {
		h.log.Err(err).Send()
	}
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

func userOrgsResponse(userOrg *action.UserOrgsResponse) *csapitypes.UserOrgsResponse {
	return &csapitypes.UserOrgsResponse{
		Organization: userOrg.Organization,
		Role:         userOrg.Role,
	}
}

type UserOrgsHandler struct {
	log zerolog.Logger
	ah  *action.ActionHandler
}

func NewUserOrgsHandler(log zerolog.Logger, ah *action.ActionHandler) *UserOrgsHandler {
	return &UserOrgsHandler{log: log, ah: ah}
}

func (h *UserOrgsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	userOrgs, err := h.ah.GetUserOrgs(ctx, userRef)
	if util.HTTPError(w, err) {
		h.log.Err(err).Send()
		return
	}

	res := make([]*csapitypes.UserOrgsResponse, len(userOrgs))
	for i, userOrg := range userOrgs {
		res[i] = userOrgsResponse(userOrg)
	}

	if err := util.HTTPResponse(w, http.StatusOK, res); err != nil {
		h.log.Err(err).Send()
	}
}
