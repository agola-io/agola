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

	"agola.io/agola/internal/db"
	action "agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/services/configstore/readdb"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	"agola.io/agola/services/configstore/types"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	errors "golang.org/x/xerrors"
)

type UserHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewUserHandler(logger *zap.Logger, readDB *readdb.ReadDB) *UserHandler {
	return &UserHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *UserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	var user *types.User
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		user, err = h.readDB.GetUser(tx, userRef)
		return err
	})
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if user == nil {
		httpError(w, util.NewErrNotExist(errors.Errorf("user %q doesn't exist", userRef)))
		return
	}

	if err := httpResponse(w, http.StatusOK, user); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type CreateUserHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewCreateUserHandler(logger *zap.Logger, ah *action.ActionHandler) *CreateUserHandler {
	return &CreateUserHandler{log: logger.Sugar(), ah: ah}
}

func (h *CreateUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req *csapitypes.CreateUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
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
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, user); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type UpdateUserHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewUpdateUserHandler(logger *zap.Logger, ah *action.ActionHandler) *UpdateUserHandler {
	return &UpdateUserHandler{log: logger.Sugar(), ah: ah}
}

func (h *UpdateUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	userRef := vars["userref"]

	var req *csapitypes.UpdateUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	creq := &action.UpdateUserRequest{
		UserRef:  userRef,
		UserName: req.UserName,
	}

	user, err := h.ah.UpdateUser(ctx, creq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, user); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type DeleteUserHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewDeleteUserHandler(logger *zap.Logger, ah *action.ActionHandler) *DeleteUserHandler {
	return &DeleteUserHandler{log: logger.Sugar(), ah: ah}
}

func (h *DeleteUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	userRef := vars["userref"]

	err := h.ah.DeleteUser(ctx, userRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
	}
	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

const (
	DefaultUsersLimit = 10
	MaxUsersLimit     = 20
)

type UsersHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewUsersHandler(logger *zap.Logger, readDB *readdb.ReadDB) *UsersHandler {
	return &UsersHandler{log: logger.Sugar(), readDB: readDB}
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
			httpError(w, util.NewErrBadRequest(errors.Errorf("cannot parse limit: %w", err)))
			return
		}
	}
	if limit < 0 {
		httpError(w, util.NewErrBadRequest(errors.Errorf("limit must be greater or equal than 0")))
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
	switch queryType {
	case "bytoken":
		token := query.Get("token")
		var user *types.User
		err := h.readDB.Do(ctx, func(tx *db.Tx) error {
			var err error
			user, err = h.readDB.GetUserByTokenValue(tx, token)
			return err
		})
		if err != nil {
			h.log.Errorf("err: %+v", err)
			httpError(w, err)
			return
		}
		if user == nil {
			httpError(w, util.NewErrNotExist(errors.Errorf("user with required token doesn't exist")))
			return
		}
		users = []*types.User{user}
	case "bylinkedaccount":
		linkedAccountID := query.Get("linkedaccountid")
		var user *types.User
		err := h.readDB.Do(ctx, func(tx *db.Tx) error {
			var err error
			user, err = h.readDB.GetUserByLinkedAccount(tx, linkedAccountID)
			return err
		})
		if err != nil {
			h.log.Errorf("err: %+v", err)
			httpError(w, err)
			return
		}
		if user == nil {
			httpError(w, util.NewErrNotExist(errors.Errorf("user with linked account %q token doesn't exist", linkedAccountID)))
			return
		}
		users = []*types.User{user}
	case "byremoteuser":
		remoteUserID := query.Get("remoteuserid")
		remoteSourceID := query.Get("remotesourceid")
		var user *types.User
		err := h.readDB.Do(ctx, func(tx *db.Tx) error {
			var err error
			user, err = h.readDB.GetUserByLinkedAccountRemoteUserIDandSource(tx, remoteUserID, remoteSourceID)
			return err
		})
		if err != nil {
			h.log.Errorf("err: %+v", err)
			httpError(w, err)
			return
		}
		if user == nil {
			httpError(w, util.NewErrNotExist(errors.Errorf("user with remote user %q for remote source %q token doesn't exist", remoteUserID, remoteSourceID)))
			return
		}
		users = []*types.User{user}
	default:
		// default query
		err := h.readDB.Do(ctx, func(tx *db.Tx) error {
			var err error
			users, err = h.readDB.GetUsers(tx, start, limit, asc)
			return err
		})
		if err != nil {
			h.log.Errorf("err: %+v", err)
			httpError(w, err)
			return
		}
	}

	if err := httpResponse(w, http.StatusOK, users); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type CreateUserLAHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewCreateUserLAHandler(logger *zap.Logger, ah *action.ActionHandler) *CreateUserLAHandler {
	return &CreateUserLAHandler{log: logger.Sugar(), ah: ah}
}

func (h *CreateUserLAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	var req csapitypes.CreateUserLARequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
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
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, user); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type DeleteUserLAHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewDeleteUserLAHandler(logger *zap.Logger, ah *action.ActionHandler) *DeleteUserLAHandler {
	return &DeleteUserLAHandler{log: logger.Sugar(), ah: ah}
}

func (h *DeleteUserLAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]
	laID := vars["laid"]

	err := h.ah.DeleteUserLA(ctx, userRef, laID)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
	}
	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type UpdateUserLAHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewUpdateUserLAHandler(logger *zap.Logger, ah *action.ActionHandler) *UpdateUserLAHandler {
	return &UpdateUserLAHandler{log: logger.Sugar(), ah: ah}
}

func (h *UpdateUserLAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]
	linkedAccountID := vars["laid"]

	var req csapitypes.UpdateUserLARequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
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
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusOK, user); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type CreateUserTokenHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewCreateUserTokenHandler(logger *zap.Logger, ah *action.ActionHandler) *CreateUserTokenHandler {
	return &CreateUserTokenHandler{log: logger.Sugar(), ah: ah}
}

func (h *CreateUserTokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	var req csapitypes.CreateUserTokenRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	token, err := h.ah.CreateUserToken(ctx, userRef, req.TokenName)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	resp := &csapitypes.CreateUserTokenResponse{
		Token: token,
	}
	if err := httpResponse(w, http.StatusCreated, resp); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type DeleteUserTokenHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewDeleteUserTokenHandler(logger *zap.Logger, ah *action.ActionHandler) *DeleteUserTokenHandler {
	return &DeleteUserTokenHandler{log: logger.Sugar(), ah: ah}
}

func (h *DeleteUserTokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]
	tokenName := vars["tokenname"]

	err := h.ah.DeleteUserToken(ctx, userRef, tokenName)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}
	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

func userOrgsResponse(userOrg *action.UserOrgsResponse) *csapitypes.UserOrgsResponse {
	return &csapitypes.UserOrgsResponse{
		Organization: userOrg.Organization,
		Role:         userOrg.Role,
	}
}

type UserOrgsHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewUserOrgsHandler(logger *zap.Logger, ah *action.ActionHandler) *UserOrgsHandler {
	return &UserOrgsHandler{log: logger.Sugar(), ah: ah}
}

func (h *UserOrgsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	userOrgs, err := h.ah.GetUserOrgs(ctx, userRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := make([]*csapitypes.UserOrgsResponse, len(userOrgs))
	for i, userOrg := range userOrgs {
		res[i] = userOrgsResponse(userOrg)
	}

	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
