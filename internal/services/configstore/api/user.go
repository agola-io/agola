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

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/configstore/command"
	"github.com/sorintlab/agola/internal/services/configstore/readdb"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type UserHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewUserHandler(logger *zap.Logger, readDB *readdb.ReadDB) *UserHandler {
	return &UserHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *UserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userid"]

	var user *types.User
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		user, err = h.readDB.GetUser(tx, userID)
		return err
	})
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if user == nil {
		httpError(w, util.NewErrNotFound(errors.Errorf("user %q doesn't exist", userID)))
		return
	}

	if err := httpResponse(w, http.StatusOK, user); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type UserByNameHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
}

func NewUserByNameHandler(logger *zap.Logger, readDB *readdb.ReadDB) *UserByNameHandler {
	return &UserByNameHandler{log: logger.Sugar(), readDB: readDB}
}

func (h *UserByNameHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userName := vars["username"]

	var user *types.User
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		user, err = h.readDB.GetUserByName(tx, userName)
		return err
	})
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	if user == nil {
		httpError(w, util.NewErrNotFound(errors.Errorf("user %q doesn't exist", userName)))
		return
	}

	if err := httpResponse(w, http.StatusOK, user); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type CreateUserRequest struct {
	UserName string `json:"user_name"`

	CreateUserLARequest *CreateUserLARequest `json:"create_user_la_request"`
}

type CreateUserHandler struct {
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

func NewCreateUserHandler(logger *zap.Logger, ch *command.CommandHandler) *CreateUserHandler {
	return &CreateUserHandler{log: logger.Sugar(), ch: ch}
}

func (h *CreateUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req *CreateUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	creq := &command.CreateUserRequest{
		UserName: req.UserName,
	}
	if req.CreateUserLARequest != nil {
		creq.CreateUserLARequest = &command.CreateUserLARequest{
			RemoteSourceName:   req.CreateUserLARequest.RemoteSourceName,
			RemoteUserID:       req.CreateUserLARequest.RemoteUserID,
			RemoteUserName:     req.CreateUserLARequest.RemoteUserName,
			Oauth2AccessToken:  req.CreateUserLARequest.Oauth2AccessToken,
			Oauth2RefreshToken: req.CreateUserLARequest.Oauth2RefreshToken,
			UserAccessToken:    req.CreateUserLARequest.UserAccessToken,
		}
	}

	user, err := h.ch.CreateUser(ctx, creq)
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
	ch  *command.CommandHandler
}

func NewDeleteUserHandler(logger *zap.Logger, ch *command.CommandHandler) *DeleteUserHandler {
	return &DeleteUserHandler{log: logger.Sugar(), ch: ch}
}

func (h *DeleteUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	userName := vars["username"]

	err := h.ch.DeleteUser(ctx, userName)
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
	query := r.URL.Query()

	limitS := query.Get("limit")
	limit := DefaultUsersLimit
	if limitS != "" {
		var err error
		limit, err = strconv.Atoi(limitS)
		if err != nil {
			httpError(w, util.NewErrBadRequest(errors.Wrapf(err, "cannot parse limit")))
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
	h.log.Infof("query_type: %s", queryType)

	var users []*types.User
	switch queryType {
	case "bytoken":
		token := query.Get("token")
		var user *types.User
		err := h.readDB.Do(func(tx *db.Tx) error {
			var err error
			user, err = h.readDB.GetUserByTokenValue(tx, token)
			return err
		})
		h.log.Infof("user: %s", util.Dump(user))
		if err != nil {
			h.log.Errorf("err: %+v", err)
			httpError(w, err)
			return
		}
		if user == nil {
			httpError(w, util.NewErrNotFound(errors.Errorf("user with required token doesn't exist")))
			return
		}
		users = []*types.User{user}
	case "bylinkedaccount":
		linkedAccountID := query.Get("linkedaccountid")
		var user *types.User
		err := h.readDB.Do(func(tx *db.Tx) error {
			var err error
			user, err = h.readDB.GetUserByLinkedAccount(tx, linkedAccountID)
			return err
		})
		h.log.Infof("user: %s", util.Dump(user))
		if err != nil {
			h.log.Errorf("err: %+v", err)
			httpError(w, err)
			return
		}
		if user == nil {
			httpError(w, util.NewErrNotFound(errors.Errorf("user with linked account %q token doesn't exist", linkedAccountID)))
			return
		}
		users = []*types.User{user}
	case "byremoteuser":
		remoteUserID := query.Get("remoteuserid")
		remoteSourceID := query.Get("remotesourceid")
		var user *types.User
		err := h.readDB.Do(func(tx *db.Tx) error {
			var err error
			user, err = h.readDB.GetUserByLinkedAccountRemoteUserIDandSource(tx, remoteUserID, remoteSourceID)
			return err
		})
		h.log.Infof("user: %s", util.Dump(user))
		if err != nil {
			h.log.Errorf("err: %+v", err)
			httpError(w, err)
			return
		}
		if user == nil {
			httpError(w, util.NewErrNotFound(errors.Errorf("user with remote user %q for remote source %q token doesn't exist", remoteUserID, remoteSourceID)))
			return
		}
		users = []*types.User{user}
	default:
		// default query
		err := h.readDB.Do(func(tx *db.Tx) error {
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

type CreateUserLARequest struct {
	RemoteSourceName   string `json:"remote_source_name"`
	RemoteUserID       string `json:"remote_user_id"`
	RemoteUserName     string `json:"remote_user_name"`
	UserAccessToken    string `json:"user_access_token"`
	Oauth2AccessToken  string `json:"oauth2_access_token"`
	Oauth2RefreshToken string `json:"oauth2_refresh_token"`
}

type CreateUserLAHandler struct {
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

func NewCreateUserLAHandler(logger *zap.Logger, ch *command.CommandHandler) *CreateUserLAHandler {
	return &CreateUserLAHandler{log: logger.Sugar(), ch: ch}
}

func (h *CreateUserLAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userName := vars["username"]

	var req CreateUserLARequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	creq := &command.CreateUserLARequest{
		UserName:           userName,
		RemoteSourceName:   req.RemoteSourceName,
		RemoteUserID:       req.RemoteUserID,
		RemoteUserName:     req.RemoteUserName,
		Oauth2AccessToken:  req.Oauth2AccessToken,
		Oauth2RefreshToken: req.Oauth2RefreshToken,
		UserAccessToken:    req.UserAccessToken,
	}
	user, err := h.ch.CreateUserLA(ctx, creq)
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
	ch  *command.CommandHandler
}

func NewDeleteUserLAHandler(logger *zap.Logger, ch *command.CommandHandler) *DeleteUserLAHandler {
	return &DeleteUserLAHandler{log: logger.Sugar(), ch: ch}
}

func (h *DeleteUserLAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userName := vars["username"]
	laID := vars["laid"]

	err := h.ch.DeleteUserLA(ctx, userName, laID)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
	}
	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type UpdateUserLARequest struct {
	RemoteUserID       string `json:"remote_user_id"`
	RemoteUserName     string `json:"remote_user_name"`
	UserAccessToken    string `json:"user_access_token"`
	Oauth2AccessToken  string `json:"oauth2_access_token"`
	Oauth2RefreshToken string `json:"oauth2_refresh_token"`
}

type UpdateUserLAHandler struct {
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

func NewUpdateUserLAHandler(logger *zap.Logger, ch *command.CommandHandler) *UpdateUserLAHandler {
	return &UpdateUserLAHandler{log: logger.Sugar(), ch: ch}
}

func (h *UpdateUserLAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userName := vars["username"]
	linkedAccountID := vars["laid"]

	var req UpdateUserLARequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	creq := &command.UpdateUserLARequest{
		UserName:           userName,
		LinkedAccountID:    linkedAccountID,
		RemoteUserID:       req.RemoteUserID,
		RemoteUserName:     req.RemoteUserName,
		Oauth2AccessToken:  req.Oauth2AccessToken,
		Oauth2RefreshToken: req.Oauth2RefreshToken,
		UserAccessToken:    req.UserAccessToken,
	}
	user, err := h.ch.UpdateUserLA(ctx, creq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusOK, user); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type CreateUserTokenRequest struct {
	TokenName string `json:"token_name"`
}

type CreateUserTokenResponse struct {
	Token string `json:"token"`
}

type CreateUserTokenHandler struct {
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

func NewCreateUserTokenHandler(logger *zap.Logger, ch *command.CommandHandler) *CreateUserTokenHandler {
	return &CreateUserTokenHandler{log: logger.Sugar(), ch: ch}
}

func (h *CreateUserTokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userName := vars["username"]

	var req CreateUserTokenRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	token, err := h.ch.CreateUserToken(ctx, userName, req.TokenName)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	resp := &CreateUserTokenResponse{
		Token: token,
	}
	if err := httpResponse(w, http.StatusCreated, resp); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type DeleteUserTokenHandler struct {
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

func NewDeleteUserTokenHandler(logger *zap.Logger, ch *command.CommandHandler) *DeleteUserTokenHandler {
	return &DeleteUserTokenHandler{log: logger.Sugar(), ch: ch}
}

func (h *DeleteUserTokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userName := vars["username"]
	tokenName := vars["tokenname"]

	err := h.ch.DeleteUserToken(ctx, userName, tokenName)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
	}
	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}
