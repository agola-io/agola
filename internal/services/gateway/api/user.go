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

	"github.com/pkg/errors"
	gitsource "github.com/sorintlab/agola/internal/gitsources"
	"github.com/sorintlab/agola/internal/services/gateway/action"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	"go.uber.org/zap"

	"github.com/gorilla/mux"
)

type CreateUserRequest struct {
	UserName string `json:"username"`
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

	var req CreateUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	creq := &action.CreateUserRequest{
		UserName: req.UserName,
	}

	u, err := h.ah.CreateUser(ctx, creq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createUserResponse(u)
	if err := httpResponse(w, http.StatusCreated, res); err != nil {
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
		return
	}

	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type CurrentUserHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewCurrentUserHandler(logger *zap.Logger, ah *action.ActionHandler) *CurrentUserHandler {
	return &CurrentUserHandler{log: logger.Sugar(), ah: ah}
}

func (h *CurrentUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userIDVal := ctx.Value("userid")
	if userIDVal == nil {
		httpError(w, util.NewErrBadRequest(errors.Errorf("user not authenticated")))
		return
	}
	userID := userIDVal.(string)

	user, err := h.ah.GetUser(ctx, userID)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createUserResponse(user)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type UserHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewUserHandler(logger *zap.Logger, ah *action.ActionHandler) *UserHandler {
	return &UserHandler{log: logger.Sugar(), ah: ah}
}

func (h *UserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	user, err := h.ah.GetUser(ctx, userRef)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := createUserResponse(user)
	if err := httpResponse(w, http.StatusOK, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type UserResponse struct {
	ID             string                   `json:"id,omitempty"`
	UserName       string                   `json:"username,omitempty"`
	Tokens         []string                 `json:"tokens,omitempty"`
	LinkedAccounts []*LinkedAccountResponse `json:"linked_accounts,omitempty"`
}

type LinkedAccountResponse struct {
	RemoteSourceID string `json:"remote_source_id,omitempty"`
}

func createUserResponse(u *types.User) *UserResponse {
	user := &UserResponse{
		ID:             u.ID,
		UserName:       u.Name,
		Tokens:         make([]string, 0, len(u.Tokens)),
		LinkedAccounts: make([]*LinkedAccountResponse, 0, len(u.LinkedAccounts)),
	}
	for tokenName := range u.Tokens {
		user.Tokens = append(user.Tokens, tokenName)
	}
	sort.Sort(sort.StringSlice(user.Tokens))

	for _, la := range u.LinkedAccounts {
		user.LinkedAccounts = append(user.LinkedAccounts, &LinkedAccountResponse{
			RemoteSourceID: la.RemoteSourceID,
		})
	}

	return user
}

type UsersHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

func NewUsersHandler(logger *zap.Logger, ah *action.ActionHandler) *UsersHandler {
	return &UsersHandler{log: logger.Sugar(), ah: ah}
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
			httpError(w, util.NewErrBadRequest(errors.Wrapf(err, "cannot parse limit")))
			return
		}
	}
	if limit < 0 {
		httpError(w, util.NewErrBadRequest(errors.Errorf("limit must be greater or equal than 0")))
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

	areq := &action.GetUsersRequest{
		Start: start,
		Limit: limit,
		Asc:   asc,
	}
	csusers, err := h.ah.GetUsers(ctx, areq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	users := make([]*UserResponse, len(csusers))
	for i, p := range csusers {
		users[i] = createUserResponse(p)
	}

	if err := httpResponse(w, http.StatusOK, users); err != nil {
		h.log.Errorf("err: %+v", err)
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
	ah  *action.ActionHandler
}

func NewCreateUserLAHandler(logger *zap.Logger, ah *action.ActionHandler) *CreateUserLAHandler {
	return &CreateUserLAHandler{log: logger.Sugar(), ah: ah}
}

func (h *CreateUserLAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	var req *CreateUserLARequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	res, err := h.createUserLA(ctx, userRef, req)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

func (h *CreateUserLAHandler) createUserLA(ctx context.Context, userRef string, req *CreateUserLARequest) (*CreateUserLAResponse, error) {
	creq := &action.CreateUserLARequest{
		UserRef:          userRef,
		RemoteSourceName: req.RemoteSourceName,
	}

	h.log.Infof("creating linked account")
	cresp, err := h.ah.HandleRemoteSourceAuth(ctx, req.RemoteSourceName, req.RemoteSourceLoginName, req.RemoteSourceLoginPassword, action.RemoteSourceRequestTypeCreateUserLA, creq)
	if err != nil {
		return nil, err
	}
	if cresp.Oauth2Redirect != "" {
		return &CreateUserLAResponse{
			Oauth2Redirect: cresp.Oauth2Redirect,
		}, nil
	}
	authresp := cresp.Response.(*action.CreateUserLAResponse)

	resp := &CreateUserLAResponse{
		LinkedAccount: authresp.LinkedAccount,
	}
	h.log.Infof("linked account %q for user %q created", resp.LinkedAccount.ID, userRef)
	return resp, nil
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
		return
	}

	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
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
	ah  *action.ActionHandler
}

func NewCreateUserTokenHandler(logger *zap.Logger, ah *action.ActionHandler) *CreateUserTokenHandler {
	return &CreateUserTokenHandler{log: logger.Sugar(), ah: ah}
}

func (h *CreateUserTokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userRef := vars["userref"]

	var req CreateUserTokenRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	creq := &action.CreateUserTokenRequest{
		UserRef:   userRef,
		TokenName: req.TokenName,
	}
	h.log.Infof("creating user %q token", userRef)
	token, err := h.ah.CreateUserToken(ctx, creq)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	res := &CreateUserTokenResponse{
		Token: token,
	}

	if err := httpResponse(w, http.StatusCreated, res); err != nil {
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

	h.log.Infof("deleting user %q token %q", userRef, tokenName)
	err := h.ah.DeleteUserToken(ctx, userRef, tokenName)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusNoContent, nil); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

type RegisterUserRequest struct {
	CreateUserRequest
	CreateUserLARequest
}

type RegisterUserHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

type RegisterUserResponse struct {
	Oauth2Redirect string `json:"oauth2_redirect"`
}

func NewRegisterUserHandler(logger *zap.Logger, ah *action.ActionHandler) *RegisterUserHandler {
	return &RegisterUserHandler{log: logger.Sugar(), ah: ah}
}

func (h *RegisterUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req *RegisterUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	res, err := h.registerUser(ctx, req)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

func (h *RegisterUserHandler) registerUser(ctx context.Context, req *RegisterUserRequest) (*RegisterUserResponse, error) {
	creq := &action.RegisterUserRequest{
		UserName:         req.CreateUserRequest.UserName,
		RemoteSourceName: req.CreateUserLARequest.RemoteSourceName,
	}

	cresp, err := h.ah.HandleRemoteSourceAuth(ctx, req.CreateUserLARequest.RemoteSourceName, req.CreateUserLARequest.RemoteSourceLoginName, req.CreateUserLARequest.RemoteSourceLoginPassword, action.RemoteSourceRequestTypeRegisterUser, creq)
	if err != nil {
		return nil, err
	}
	if cresp.Oauth2Redirect != "" {
		return &RegisterUserResponse{
			Oauth2Redirect: cresp.Oauth2Redirect,
		}, nil
	}
	//authresp := cresp.Response.(*action.RegisterUserResponse)

	resp := &RegisterUserResponse{}
	return resp, nil
}

type AuthorizeHandler struct {
	log *zap.SugaredLogger
	ah  *action.ActionHandler
}

type AuthorizeResponse struct {
	Oauth2Redirect   string              `json:"oauth2_redirect"`
	RemoteUserInfo   *gitsource.UserInfo `json:"remote_user_info"`
	RemoteSourceName string              `json:"remote_source_name"`
}

func NewAuthorizeHandler(logger *zap.Logger, ah *action.ActionHandler) *AuthorizeHandler {
	return &AuthorizeHandler{log: logger.Sugar(), ah: ah}
}

func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req *LoginUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	res, err := h.authorize(ctx, req)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

func (h *AuthorizeHandler) authorize(ctx context.Context, req *LoginUserRequest) (*AuthorizeResponse, error) {
	creq := &action.LoginUserRequest{
		RemoteSourceName: req.RemoteSourceName,
	}

	cresp, err := h.ah.HandleRemoteSourceAuth(ctx, req.RemoteSourceName, req.LoginName, req.LoginPassword, action.RemoteSourceRequestTypeAuthorize, creq)
	if err != nil {
		return nil, err
	}
	if cresp.Oauth2Redirect != "" {
		return &AuthorizeResponse{
			Oauth2Redirect: cresp.Oauth2Redirect,
		}, nil
	}
	authresp := cresp.Response.(*action.AuthorizeResponse)

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
	ah  *action.ActionHandler
}

func NewLoginUserHandler(logger *zap.Logger, ah *action.ActionHandler) *LoginUserHandler {
	return &LoginUserHandler{log: logger.Sugar(), ah: ah}
}

func (h *LoginUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req *LoginUserRequest
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&req); err != nil {
		httpError(w, util.NewErrBadRequest(err))
		return
	}

	res, err := h.loginUser(ctx, req)
	if httpError(w, err) {
		h.log.Errorf("err: %+v", err)
		return
	}

	if err := httpResponse(w, http.StatusCreated, res); err != nil {
		h.log.Errorf("err: %+v", err)
	}
}

func (h *LoginUserHandler) loginUser(ctx context.Context, req *LoginUserRequest) (*LoginUserResponse, error) {
	creq := &action.LoginUserRequest{
		RemoteSourceName: req.RemoteSourceName,
	}

	h.log.Infof("logging in user")
	cresp, err := h.ah.HandleRemoteSourceAuth(ctx, req.RemoteSourceName, req.LoginName, req.LoginPassword, action.RemoteSourceRequestTypeLoginUser, creq)
	if err != nil {
		return nil, err
	}
	if cresp.Oauth2Redirect != "" {
		return &LoginUserResponse{
			Oauth2Redirect: cresp.Oauth2Redirect,
		}, nil
	}
	authresp := cresp.Response.(*action.LoginUserResponse)

	resp := &LoginUserResponse{
		Token: authresp.Token,
		User:  createUserResponse(authresp.User),
	}
	return resp, nil
}
