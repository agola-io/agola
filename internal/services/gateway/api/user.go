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
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/command"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	"go.uber.org/zap"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

type CreateUserRequest struct {
	UserName string `json:"username"`
}

type CreateUserHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewCreateUserHandler(logger *zap.Logger, configstoreClient *csapi.Client) *CreateUserHandler {
	return &CreateUserHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *CreateUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.createUser(ctx, &req)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (h *CreateUserHandler) createUser(ctx context.Context, req *CreateUserRequest) (*UserResponse, error) {
	if !util.ValidateName(req.UserName) {
		return nil, errors.Errorf("invalid user name %q", req.UserName)
	}

	u := &types.User{
		UserName: req.UserName,
	}

	h.log.Infof("creating user")
	u, _, err := h.configstoreClient.CreateUser(ctx, u)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create user")
	}
	h.log.Infof("user %s created, ID: %s", u.UserName, u.ID)

	res := createUserResponse(u)
	return res, nil
}

type DeleteUserHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewDeleteUserHandler(logger *zap.Logger, configstoreClient *csapi.Client) *DeleteUserHandler {
	return &DeleteUserHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *DeleteUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userName := vars["username"]

	resp, err := h.configstoreClient.DeleteUser(ctx, userName)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type CurrentUserHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewCurrentUserHandler(logger *zap.Logger, configstoreClient *csapi.Client) *CurrentUserHandler {
	return &CurrentUserHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *CurrentUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userIDVal := ctx.Value("userid")
	if userIDVal == nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	userID := userIDVal.(string)

	user, resp, err := h.configstoreClient.GetUser(ctx, userID)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := createUserResponse(user)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type UserHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewUserHandler(logger *zap.Logger, configstoreClient *csapi.Client) *UserHandler {
	return &UserHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *UserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userID := vars["userid"]

	user, resp, err := h.configstoreClient.GetUser(ctx, userID)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := createUserResponse(user)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type UserByNameHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewUserByNameHandler(logger *zap.Logger, configstoreClient *csapi.Client) *UserByNameHandler {
	return &UserByNameHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *UserByNameHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userName := vars["username"]

	user, resp, err := h.configstoreClient.GetUserByName(ctx, userName)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := createUserResponse(user)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type UsersResponse struct {
	Users []*UserResponse `json:"users"`
}

type UserResponse struct {
	ID       string `json:"id"`
	UserName string `json:"username"`
}

func createUserResponse(r *types.User) *UserResponse {
	user := &UserResponse{
		ID:       r.ID,
		UserName: r.UserName,
	}
	return user
}

type UsersHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewUsersHandler(logger *zap.Logger, configstoreClient *csapi.Client) *UsersHandler {
	return &UsersHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *UsersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	query := r.URL.Query()

	limitS := query.Get("limit")
	limit := DefaultRunsLimit
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
	if limit > MaxRunsLimit {
		limit = MaxRunsLimit
	}
	asc := false
	if _, ok := query["asc"]; ok {
		asc = true
	}

	start := query.Get("start")

	csusers, resp, err := h.configstoreClient.GetUsers(ctx, start, limit, asc)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	users := make([]*UserResponse, len(csusers))
	for i, p := range csusers {
		users[i] = createUserResponse(p)
	}
	usersResponse := &UsersResponse{
		Users: users,
	}

	if err := json.NewEncoder(w).Encode(usersResponse); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type CreateUserLARequest struct {
	RemoteSourceName          string `json:"remote_source_name"`
	RemoteSourceLoginName     string `json:"remote_login_name"`
	RemoteSourceLoginPassword string `json:"remote_login_password"`
}

type CreateUserLAResponse struct {
	LinkedAccount  *types.LinkedAccount `json:"linked_account"`
	Oauth2Redirect string               `json:"oauth2_redirect"`
}

type CreateUserLAHandler struct {
	log               *zap.SugaredLogger
	ch                *command.CommandHandler
	configstoreClient *csapi.Client
}

func NewCreateUserLAHandler(logger *zap.Logger, ch *command.CommandHandler, configstoreClient *csapi.Client) *CreateUserLAHandler {
	return &CreateUserLAHandler{log: logger.Sugar(), ch: ch, configstoreClient: configstoreClient}
}

func (h *CreateUserLAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userName := vars["username"]

	var req *CreateUserLARequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := h.createUserLA(ctx, userName, req)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (h *CreateUserLAHandler) createUserLA(ctx context.Context, userName string, req *CreateUserLARequest) (*CreateUserLAResponse, error) {
	remoteSourceName := req.RemoteSourceName
	user, _, err := h.configstoreClient.GetUserByName(ctx, userName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user %q", userName)
	}
	rs, _, err := h.configstoreClient.GetRemoteSourceByName(ctx, remoteSourceName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get remote source %q", remoteSourceName)
	}
	h.log.Infof("rs: %s", util.Dump(rs))
	var la *types.LinkedAccount
	for _, v := range user.LinkedAccounts {
		if v.RemoteSourceID == rs.ID {
			la = v
			break
		}
	}
	h.log.Infof("la: %s", util.Dump(la))
	if la != nil {
		return nil, errors.Errorf("user %q already have a linked account for remote source %q", userName, rs.Name)
	}

	creq := &command.CreateUserLARequest{
		UserName:         userName,
		RemoteSourceName: rs.Name,
	}

	h.log.Infof("creating linked account")
	cresp, err := h.ch.HandleRemoteSourceAuth(ctx, rs, req.RemoteSourceLoginName, req.RemoteSourceLoginPassword, "createuserla", creq)
	if err != nil {
		return nil, err
	}
	if cresp.Oauth2Redirect != "" {
		return &CreateUserLAResponse{
			Oauth2Redirect: cresp.Oauth2Redirect,
		}, nil
	}
	authresp := cresp.Response.(*command.CreateUserLAResponse)

	resp := &CreateUserLAResponse{
		LinkedAccount: authresp.LinkedAccount,
	}
	h.log.Infof("linked account %q for user %q created", resp.LinkedAccount.ID, userName)
	return resp, nil
}

type DeleteUserLAHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewDeleteUserLAHandler(logger *zap.Logger, configstoreClient *csapi.Client) *DeleteUserLAHandler {
	return &DeleteUserLAHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *DeleteUserLAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userName := vars["username"]
	laID := vars["laid"]

	_, err := h.configstoreClient.DeleteUserLA(ctx, userName, laID)
	if err != nil {
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
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewCreateUserTokenHandler(logger *zap.Logger, configstoreClient *csapi.Client) *CreateUserTokenHandler {
	return &CreateUserTokenHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
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

	creq := &csapi.CreateUserTokenRequest{
		TokenName: req.TokenName,
	}
	h.log.Infof("creating user %q token", userName)
	cresp, _, err := h.configstoreClient.CreateUserToken(ctx, userName, creq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.log.Infof("user %q token created", userName)

	resp := &CreateUserTokenResponse{
		Token: cresp.Token,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type LoginUserRequest struct {
	RemoteSourceName string `json:"remote_source_name"`
	LoginName        string `json:"login_name"`
	LoginPassword    string `json:"password"`
}

type LoginUserResponse struct {
	Oauth2Redirect string        `json:"oauth2_redirect"`
	Token          string        `json:"token"`
	User           *UserResponse `json:"user"`
}

type LoginUserHandler struct {
	log               *zap.SugaredLogger
	ch                *command.CommandHandler
	configstoreClient *csapi.Client
}

func NewLoginUserHandler(logger *zap.Logger, ch *command.CommandHandler, configstoreClient *csapi.Client) *LoginUserHandler {
	return &LoginUserHandler{log: logger.Sugar(), ch: ch, configstoreClient: configstoreClient}
}

func (h *LoginUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req *LoginUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := h.loginUser(ctx, req)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (h *LoginUserHandler) loginUser(ctx context.Context, req *LoginUserRequest) (*LoginUserResponse, error) {
	remoteSourceName := req.RemoteSourceName
	rs, _, err := h.configstoreClient.GetRemoteSourceByName(ctx, remoteSourceName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get remote source %q", remoteSourceName)
	}
	h.log.Infof("rs: %s", util.Dump(rs))

	creq := &command.LoginUserRequest{
		RemoteSourceName: rs.Name,
	}

	h.log.Infof("logging in user")
	cresp, err := h.ch.HandleRemoteSourceAuth(ctx, rs, req.LoginName, req.LoginPassword, "loginuser", creq)
	if err != nil {
		return nil, err
	}
	if cresp.Oauth2Redirect != "" {
		return &LoginUserResponse{
			Oauth2Redirect: cresp.Oauth2Redirect,
		}, nil
	}
	authresp := cresp.Response.(*command.LoginUserResponse)

	resp := &LoginUserResponse{
		Token: authresp.Token,
		User:  createUserResponse(authresp.User),
	}
	return resp, nil
}

type RemoteSourceAuthResponse struct {
	Oauth2Redirect string      `json:"oauth_2_redirect"`
	Response       interface{} `json:"response"`
}
