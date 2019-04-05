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
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"

	gitsource "github.com/sorintlab/agola/internal/gitsources"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/command"
	"github.com/sorintlab/agola/internal/services/types"
	"go.uber.org/zap"

	"github.com/gorilla/mux"
)

type CreateUserRequest struct {
	UserName string `json:"username"`
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

	var req CreateUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	creq := &command.CreateUserRequest{
		UserName: req.UserName,
	}

	u, err := h.ch.CreateUser(ctx, creq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createUserResponse(u)

	if err := json.NewEncoder(w).Encode(res); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	res := createUserResponse(user)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	res := createUserResponse(user)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	res := createUserResponse(user)
	if err := json.NewEncoder(w).Encode(res); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

type UserResponse struct {
	ID       string   `json:"id"`
	UserName string   `json:"username"`
	Tokens   []string `json:"tokens"`
}

func createUserResponse(u *types.User) *UserResponse {
	user := &UserResponse{
		ID:       u.ID,
		UserName: u.UserName,
		Tokens:   make([]string, 0, len(u.Tokens)),
	}
	for tokenName := range u.Tokens {
		user.Tokens = append(user.Tokens, tokenName)
	}
	sort.Sort(sort.StringSlice(user.Tokens))

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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

	users := make([]*UserResponse, len(csusers))
	for i, p := range csusers {
		users[i] = createUserResponse(p)
	}

	if err := json.NewEncoder(w).Encode(users); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

type CreateUserLARequest struct {
	RemoteSourceName          string `json:"remote_source_name"`
	RemoteSourceLoginName     string `json:"remote_source_login_name"`
	RemoteSourceLoginPassword string `json:"remote_source_login_password"`
}

type CreateUserLAResponse struct {
	LinkedAccount  *types.LinkedAccount `json:"linked_account"`
	Oauth2Redirect string               `json:"oauth2_redirect"`
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

}

func (h *CreateUserLAHandler) createUserLA(ctx context.Context, userName string, req *CreateUserLARequest) (*CreateUserLAResponse, error) {
	creq := &command.CreateUserLARequest{
		UserName:         userName,
		RemoteSourceName: req.RemoteSourceName,
	}

	h.log.Infof("creating linked account")
	cresp, err := h.ch.HandleRemoteSourceAuth(ctx, req.RemoteSourceName, req.RemoteSourceLoginName, req.RemoteSourceLoginPassword, command.RemoteSourceRequestTypeCreateUserLA, creq)
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
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

	creq := &command.CreateUserTokenRequest{
		UserName:  userName,
		TokenName: req.TokenName,
	}
	h.log.Infof("creating user %q token", userName)
	token, err := h.ch.CreateUserToken(ctx, creq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	resp := &CreateUserTokenResponse{
		Token: token,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

type DeleteUserTokenHandler struct {
	log               *zap.SugaredLogger
	configstoreClient *csapi.Client
}

func NewDeleteUserTokenHandler(logger *zap.Logger, configstoreClient *csapi.Client) *DeleteUserTokenHandler {
	return &DeleteUserTokenHandler{log: logger.Sugar(), configstoreClient: configstoreClient}
}

func (h *DeleteUserTokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userName := vars["username"]
	tokenName := vars["tokenname"]

	h.log.Infof("deleting user %q token %q", userName, tokenName)
	_, err := h.configstoreClient.DeleteUserToken(ctx, userName, tokenName)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

type RegisterUserRequest struct {
	CreateUserRequest
	CreateUserLARequest
}

type RegisterUserHandler struct {
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

type RegisterUserResponse struct {
	Oauth2Redirect string `json:"oauth2_redirect"`
}

func NewRegisterUserHandler(logger *zap.Logger, ch *command.CommandHandler) *RegisterUserHandler {
	return &RegisterUserHandler{log: logger.Sugar(), ch: ch}
}

func (h *RegisterUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req *RegisterUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := h.registerUser(ctx, req)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}
}

func (h *RegisterUserHandler) registerUser(ctx context.Context, req *RegisterUserRequest) (*RegisterUserResponse, error) {
	creq := &command.RegisterUserRequest{
		UserName:         req.CreateUserRequest.UserName,
		RemoteSourceName: req.CreateUserLARequest.RemoteSourceName,
	}

	cresp, err := h.ch.HandleRemoteSourceAuth(ctx, req.CreateUserLARequest.RemoteSourceName, req.CreateUserLARequest.RemoteSourceLoginName, req.CreateUserLARequest.RemoteSourceLoginPassword, command.RemoteSourceRequestTypeRegisterUser, creq)
	if err != nil {
		return nil, err
	}
	if cresp.Oauth2Redirect != "" {
		return &RegisterUserResponse{
			Oauth2Redirect: cresp.Oauth2Redirect,
		}, nil
	}
	//authresp := cresp.Response.(*command.RegisterUserResponse)

	resp := &RegisterUserResponse{}
	return resp, nil
}

type AuthorizeHandler struct {
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

type AuthorizeResponse struct {
	Oauth2Redirect   string              `json:"oauth2_redirect"`
	RemoteUserInfo   *gitsource.UserInfo `json:"remote_user_info"`
	RemoteSourceName string              `json:"remote_source_name"`
}

func NewAuthorizeHandler(logger *zap.Logger, ch *command.CommandHandler) *AuthorizeHandler {
	return &AuthorizeHandler{log: logger.Sugar(), ch: ch}
}

func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req *LoginUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := h.authorize(ctx, req)
	if err != nil {
		h.log.Errorf("err: %+v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

}

func (h *AuthorizeHandler) authorize(ctx context.Context, req *LoginUserRequest) (*AuthorizeResponse, error) {
	creq := &command.LoginUserRequest{
		RemoteSourceName: req.RemoteSourceName,
	}

	cresp, err := h.ch.HandleRemoteSourceAuth(ctx, req.RemoteSourceName, req.LoginName, req.LoginPassword, command.RemoteSourceRequestTypeAuthorize, creq)
	if err != nil {
		return nil, err
	}
	if cresp.Oauth2Redirect != "" {
		return &AuthorizeResponse{
			Oauth2Redirect: cresp.Oauth2Redirect,
		}, nil
	}
	authresp := cresp.Response.(*command.AuthorizeResponse)

	resp := &AuthorizeResponse{
		RemoteUserInfo:   authresp.RemoteUserInfo,
		RemoteSourceName: authresp.RemoteSourceName,
	}
	return resp, nil
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
	log *zap.SugaredLogger
	ch  *command.CommandHandler
}

func NewLoginUserHandler(logger *zap.Logger, ch *command.CommandHandler) *LoginUserHandler {
	return &LoginUserHandler{log: logger.Sugar(), ch: ch}
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
		h.log.Errorf("err: %+v", err)
		httpError(w, err)
		return
	}

}

func (h *LoginUserHandler) loginUser(ctx context.Context, req *LoginUserRequest) (*LoginUserResponse, error) {

	creq := &command.LoginUserRequest{
		RemoteSourceName: req.RemoteSourceName,
	}

	h.log.Infof("logging in user")
	cresp, err := h.ch.HandleRemoteSourceAuth(ctx, req.RemoteSourceName, req.LoginName, req.LoginPassword, command.RemoteSourceRequestTypeLoginUser, creq)
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
