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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(user); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(user); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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

	var req types.User
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.ch.CreateUser(ctx, &req)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(user); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
	h.log.Infof("deleteuserhandler")
	ctx := r.Context()

	vars := mux.Vars(r)
	userName := vars["username"]

	if err := h.ch.DeleteUser(ctx, userName); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
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
			http.Error(w, "", http.StatusBadRequest)
			return
		}
	}
	if limit < 0 {
		http.Error(w, "limit must be greater or equal than 0", http.StatusBadRequest)
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
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if user == nil {
			http.Error(w, "", http.StatusNotFound)
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
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if user == nil {
			http.Error(w, "", http.StatusNotFound)
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
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if user == nil {
			http.Error(w, "", http.StatusNotFound)
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
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if err := json.NewEncoder(w).Encode(users); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(user); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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

	if err := h.ch.DeleteUserLA(ctx, userName, laID); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
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
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(user); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := h.ch.CreateUserToken(ctx, userName, req.TokenName)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp := &CreateUserTokenResponse{
		Token: token,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
