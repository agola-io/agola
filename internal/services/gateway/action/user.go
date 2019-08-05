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

package action

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	gitsource "agola.io/agola/internal/gitsources"
	"agola.io/agola/internal/gitsources/agolagit"
	"agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/types"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"

	jwt "github.com/dgrijalva/jwt-go"
	errors "golang.org/x/xerrors"
)

const (
	expireTimeRange time.Duration = 5 * time.Minute
)

func isAccessTokenExpired(expiresAt time.Time) bool {
	if expiresAt.IsZero() {
		return false
	}
	return expiresAt.Add(-expireTimeRange).Before(time.Now())
}

func (h *ActionHandler) GetUser(ctx context.Context, userRef string) (*cstypes.User, error) {
	if !h.IsUserLoggedOrAdmin(ctx) {
		return nil, errors.Errorf("user not logged in")
	}

	user, resp, err := h.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	return user, nil
}

type GetUsersRequest struct {
	Start string
	Limit int
	Asc   bool
}

func (h *ActionHandler) GetUsers(ctx context.Context, req *GetUsersRequest) ([]*cstypes.User, error) {
	if !h.IsUserAdmin(ctx) {
		return nil, errors.Errorf("user not logged in")
	}

	users, resp, err := h.configstoreClient.GetUsers(ctx, req.Start, req.Limit, req.Asc)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	return users, nil
}

type CreateUserRequest struct {
	UserName string
}

func (h *ActionHandler) CreateUser(ctx context.Context, req *CreateUserRequest) (*cstypes.User, error) {
	if !h.IsUserAdmin(ctx) {
		return nil, errors.Errorf("user not admin")
	}

	if req.UserName == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("user name required"))
	}
	if !util.ValidateName(req.UserName) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid user name %q", req.UserName))
	}

	creq := &csapitypes.CreateUserRequest{
		UserName: req.UserName,
	}

	h.log.Infof("creating user")
	u, resp, err := h.configstoreClient.CreateUser(ctx, creq)
	if err != nil {
		return nil, errors.Errorf("failed to create user: %w", ErrFromRemote(resp, err))
	}
	h.log.Infof("user %s created, ID: %s", u.Name, u.ID)

	return u, nil
}

type CreateUserTokenRequest struct {
	UserRef   string
	TokenName string
}

func (h *ActionHandler) CreateUserToken(ctx context.Context, req *CreateUserTokenRequest) (string, error) {
	var userID string
	userIDVal := ctx.Value("userid")
	if userIDVal != nil {
		userID = userIDVal.(string)
	}

	isAdmin := false
	isAdminVal := ctx.Value("admin")
	if isAdminVal != nil {
		isAdmin = isAdminVal.(bool)
	}

	userRef := req.UserRef
	user, resp, err := h.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return "", errors.Errorf("failed to get user: %w", ErrFromRemote(resp, err))
	}

	// only admin or the same logged user can create a token
	if !isAdmin && user.ID != userID {
		return "", util.NewErrBadRequest(errors.Errorf("logged in user cannot create token for another user"))
	}
	if _, ok := user.Tokens[req.TokenName]; ok {
		return "", util.NewErrBadRequest(errors.Errorf("user %q already have a token with name %q", userRef, req.TokenName))
	}

	h.log.Infof("creating user token")
	creq := &csapitypes.CreateUserTokenRequest{
		TokenName: req.TokenName,
	}
	res, resp, err := h.configstoreClient.CreateUserToken(ctx, userRef, creq)
	if err != nil {
		return "", errors.Errorf("failed to create user token: %w", ErrFromRemote(resp, err))
	}
	h.log.Infof("token %q for user %q created", req.TokenName, userRef)

	return res.Token, nil
}

type CreateUserLARequest struct {
	UserRef string

	RemoteSourceName           string
	UserAccessToken            string
	Oauth2AccessToken          string
	Oauth2RefreshToken         string
	Oauth2AccessTokenExpiresAt time.Time
}

func (h *ActionHandler) CreateUserLA(ctx context.Context, req *CreateUserLARequest) (*cstypes.LinkedAccount, error) {
	userRef := req.UserRef
	user, resp, err := h.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return nil, errors.Errorf("failed to get user %q: %w", userRef, ErrFromRemote(resp, err))
	}
	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, errors.Errorf("failed to get remote source %q: %w", req.RemoteSourceName, ErrFromRemote(resp, err))
	}
	var la *cstypes.LinkedAccount
	for _, v := range user.LinkedAccounts {
		if v.RemoteSourceID == rs.ID {
			la = v
			break
		}
	}
	if la != nil {
		return nil, util.NewErrBadRequest(errors.Errorf("user %q already have a linked account for remote source %q", userRef, rs.Name))
	}

	accessToken, err := common.GetAccessToken(rs, req.UserAccessToken, req.Oauth2AccessToken)
	if err != nil {
		return nil, err
	}
	userSource, err := common.GetUserSource(rs, accessToken)
	if err != nil {
		return nil, err
	}

	remoteUserInfo, err := userSource.GetUserInfo()
	if err != nil {
		return nil, errors.Errorf("failed to retrieve remote user info for remote source %q: %w", rs.ID, err)
	}
	if remoteUserInfo.ID == "" {
		return nil, errors.Errorf("empty remote user id for remote source %q", rs.ID)
	}

	creq := &csapitypes.CreateUserLARequest{
		RemoteSourceName:           req.RemoteSourceName,
		RemoteUserID:               remoteUserInfo.ID,
		RemoteUserName:             remoteUserInfo.LoginName,
		UserAccessToken:            req.UserAccessToken,
		Oauth2AccessToken:          req.Oauth2AccessToken,
		Oauth2RefreshToken:         req.Oauth2RefreshToken,
		Oauth2AccessTokenExpiresAt: req.Oauth2AccessTokenExpiresAt,
	}

	h.log.Infof("creating linked account")
	la, resp, err = h.configstoreClient.CreateUserLA(ctx, userRef, creq)
	if err != nil {
		return nil, errors.Errorf("failed to create linked account: %w", ErrFromRemote(resp, err))
	}
	h.log.Infof("linked account %q for user %q created", la.ID, userRef)

	return la, nil
}

func (h *ActionHandler) UpdateUserLA(ctx context.Context, userRef string, la *cstypes.LinkedAccount) error {
	user, resp, err := h.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return errors.Errorf("failed to get user %q: %w", userRef, ErrFromRemote(resp, err))
	}
	laFound := false
	for _, ula := range user.LinkedAccounts {
		if ula.ID == la.ID {
			laFound = true
			break
		}
	}
	if !laFound {
		return util.NewErrBadRequest(errors.Errorf("user %q doesn't have a linked account with id %q", userRef, la.ID))
	}

	creq := &csapitypes.UpdateUserLARequest{
		RemoteUserID:               la.RemoteUserID,
		RemoteUserName:             la.RemoteUserName,
		UserAccessToken:            la.UserAccessToken,
		Oauth2AccessToken:          la.Oauth2AccessToken,
		Oauth2RefreshToken:         la.Oauth2RefreshToken,
		Oauth2AccessTokenExpiresAt: la.Oauth2AccessTokenExpiresAt,
	}

	h.log.Infof("updating user %q linked account", userRef)
	la, resp, err = h.configstoreClient.UpdateUserLA(ctx, userRef, la.ID, creq)
	if err != nil {
		return errors.Errorf("failed to update user: %w", ErrFromRemote(resp, err))
	}
	h.log.Infof("linked account %q for user %q updated", la.ID, userRef)

	return nil
}

// RefreshLinkedAccount refreshed the linked account oauth2 access token and update linked account in the configstore
func (h *ActionHandler) RefreshLinkedAccount(ctx context.Context, rs *cstypes.RemoteSource, userName string, la *cstypes.LinkedAccount) (*cstypes.LinkedAccount, error) {
	switch rs.AuthType {
	case cstypes.RemoteSourceAuthTypeOauth2:
		// refresh access token if expired
		if isAccessTokenExpired(la.Oauth2AccessTokenExpiresAt) {
			userSource, err := common.GetOauth2Source(rs, "")
			if err != nil {
				return nil, err
			}
			token, err := userSource.RefreshOauth2Token(la.Oauth2RefreshToken)
			if err != nil {
				return nil, err
			}

			if la.Oauth2AccessToken != token.AccessToken {
				la.Oauth2AccessToken = token.AccessToken
				la.Oauth2RefreshToken = token.RefreshToken
				la.Oauth2AccessTokenExpiresAt = token.Expiry

				if err := h.UpdateUserLA(ctx, userName, la); err != nil {
					return nil, errors.Errorf("failed to update linked account: %w", err)
				}
			}
		}
	}
	return la, nil
}

// GetGitSource is a wrapper around common.GetGitSource that will also refresh
// the oauth2 access token and update the linked account when needed
func (h *ActionHandler) GetGitSource(ctx context.Context, rs *cstypes.RemoteSource, userName string, la *cstypes.LinkedAccount) (gitsource.GitSource, error) {
	la, err := h.RefreshLinkedAccount(ctx, rs, userName, la)
	if err != nil {
		return nil, err
	}
	return common.GetGitSource(rs, la)
}

type RegisterUserRequest struct {
	UserName                   string
	RemoteSourceName           string
	UserAccessToken            string
	Oauth2AccessToken          string
	Oauth2RefreshToken         string
	Oauth2AccessTokenExpiresAt time.Time
}

func (h *ActionHandler) RegisterUser(ctx context.Context, req *RegisterUserRequest) (*cstypes.User, error) {
	if req.UserName == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("user name required"))
	}
	if !util.ValidateName(req.UserName) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid user name %q", req.UserName))
	}

	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, errors.Errorf("failed to get remote source %q: %w", req.RemoteSourceName, ErrFromRemote(resp, err))
	}
	if !*rs.RegistrationEnabled {
		return nil, util.NewErrBadRequest(errors.Errorf("remote source user registration is disabled"))
	}

	accessToken, err := common.GetAccessToken(rs, req.UserAccessToken, req.Oauth2AccessToken)
	if err != nil {
		return nil, err
	}
	userSource, err := common.GetUserSource(rs, accessToken)
	if err != nil {
		return nil, err
	}

	remoteUserInfo, err := userSource.GetUserInfo()
	if err != nil {
		return nil, errors.Errorf("failed to retrieve remote user info for remote source %q: %w", rs.ID, err)
	}
	if remoteUserInfo.ID == "" {
		return nil, errors.Errorf("empty remote user id for remote source %q", rs.ID)
	}

	creq := &csapitypes.CreateUserRequest{
		UserName: req.UserName,
		CreateUserLARequest: &csapitypes.CreateUserLARequest{
			RemoteSourceName:           req.RemoteSourceName,
			RemoteUserID:               remoteUserInfo.ID,
			RemoteUserName:             remoteUserInfo.LoginName,
			UserAccessToken:            req.UserAccessToken,
			Oauth2AccessToken:          req.Oauth2AccessToken,
			Oauth2RefreshToken:         req.Oauth2RefreshToken,
			Oauth2AccessTokenExpiresAt: req.Oauth2AccessTokenExpiresAt,
		},
	}

	h.log.Infof("creating user account")
	u, resp, err := h.configstoreClient.CreateUser(ctx, creq)
	if err != nil {
		return nil, errors.Errorf("failed to create linked account: %w", ErrFromRemote(resp, err))
	}
	h.log.Infof("user %q created", req.UserName)

	return u, nil
}

type LoginUserRequest struct {
	RemoteSourceName           string
	UserAccessToken            string
	Oauth2AccessToken          string
	Oauth2RefreshToken         string
	Oauth2AccessTokenExpiresAt time.Time
}

type LoginUserResponse struct {
	Token string
	User  *cstypes.User
}

func (h *ActionHandler) LoginUser(ctx context.Context, req *LoginUserRequest) (*LoginUserResponse, error) {
	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, errors.Errorf("failed to get remote source %q: %w", req.RemoteSourceName, ErrFromRemote(resp, err))
	}
	if !*rs.LoginEnabled {
		return nil, util.NewErrBadRequest(errors.Errorf("remote source user login is disabled"))
	}

	accessToken, err := common.GetAccessToken(rs, req.UserAccessToken, req.Oauth2AccessToken)
	if err != nil {
		return nil, err
	}
	userSource, err := common.GetUserSource(rs, accessToken)
	if err != nil {
		return nil, err
	}

	remoteUserInfo, err := userSource.GetUserInfo()
	if err != nil {
		return nil, errors.Errorf("failed to retrieve remote user info for remote source %q: %w", rs.ID, err)
	}
	if remoteUserInfo.ID == "" {
		return nil, errors.Errorf("empty remote user id for remote source %q", rs.ID)
	}

	user, resp, err := h.configstoreClient.GetUserByLinkedAccountRemoteUserAndSource(ctx, remoteUserInfo.ID, rs.ID)
	if err != nil {
		return nil, errors.Errorf("failed to get user for remote user id %q and remote source %q: %w", remoteUserInfo.ID, rs.ID, ErrFromRemote(resp, err))
	}

	var la *cstypes.LinkedAccount
	for _, v := range user.LinkedAccounts {
		if v.RemoteSourceID == rs.ID {
			la = v
			break
		}
	}
	if la == nil {
		return nil, errors.Errorf("linked account for user %q for remote source %q doesn't exist", user.Name, rs.Name)
	}

	// Update oauth tokens if they have changed since the getuserinfo request may have updated them
	if la.Oauth2AccessToken != req.Oauth2AccessToken ||
		la.Oauth2RefreshToken != req.Oauth2RefreshToken ||
		la.UserAccessToken != req.UserAccessToken {

		la.Oauth2AccessToken = req.Oauth2AccessToken
		la.Oauth2RefreshToken = req.Oauth2RefreshToken
		la.UserAccessToken = req.UserAccessToken

		creq := &csapitypes.UpdateUserLARequest{
			RemoteUserID:               la.RemoteUserID,
			RemoteUserName:             la.RemoteUserName,
			UserAccessToken:            la.UserAccessToken,
			Oauth2AccessToken:          la.Oauth2AccessToken,
			Oauth2RefreshToken:         la.Oauth2RefreshToken,
			Oauth2AccessTokenExpiresAt: la.Oauth2AccessTokenExpiresAt,
		}

		h.log.Infof("updating user %q linked account", user.Name)
		la, resp, err = h.configstoreClient.UpdateUserLA(ctx, user.Name, la.ID, creq)
		if err != nil {
			return nil, errors.Errorf("failed to update user: %w", ErrFromRemote(resp, err))
		}
		h.log.Infof("linked account %q for user %q updated", la.ID, user.Name)
	}

	// generate jwt token
	token, err := common.GenerateLoginJWTToken(h.sd, user.ID)
	if err != nil {
		return nil, err
	}
	return &LoginUserResponse{
		Token: token,
		User:  user,
	}, nil
}

type AuthorizeRequest struct {
	RemoteSourceName           string
	UserAccessToken            string
	Oauth2AccessToken          string
	Oauth2RefreshToken         string
	Oauth2AccessTokenExpiresAt time.Time
}

type AuthorizeResponse struct {
	RemoteUserInfo   *gitsource.UserInfo
	RemoteSourceName string
}

func (h *ActionHandler) Authorize(ctx context.Context, req *AuthorizeRequest) (*AuthorizeResponse, error) {
	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, errors.Errorf("failed to get remote source %q: %w", req.RemoteSourceName, ErrFromRemote(resp, err))
	}

	accessToken, err := common.GetAccessToken(rs, req.UserAccessToken, req.Oauth2AccessToken)
	if err != nil {
		return nil, err
	}
	userSource, err := common.GetUserSource(rs, accessToken)
	if err != nil {
		return nil, err
	}

	remoteUserInfo, err := userSource.GetUserInfo()
	if err != nil {
		return nil, errors.Errorf("failed to retrieve remote user info for remote source %q: %w", rs.ID, err)
	}
	if remoteUserInfo.ID == "" {
		return nil, errors.Errorf("empty remote user id for remote source %q", rs.ID)
	}

	return &AuthorizeResponse{
		RemoteUserInfo:   remoteUserInfo,
		RemoteSourceName: req.RemoteSourceName,
	}, nil
}

type RemoteSourceAuthResponse struct {
	Oauth2Redirect string
	Response       interface{}
}

func (h *ActionHandler) HandleRemoteSourceAuth(ctx context.Context, remoteSourceName, loginName, loginPassword string, requestType RemoteSourceRequestType, req interface{}) (*RemoteSourceAuthResponse, error) {
	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, remoteSourceName)
	if err != nil {
		return nil, errors.Errorf("failed to get remote source %q: %w", remoteSourceName, ErrFromRemote(resp, err))
	}

	switch requestType {
	case RemoteSourceRequestTypeCreateUserLA:
		req := req.(*CreateUserLARequest)

		user, resp, err := h.configstoreClient.GetUser(ctx, req.UserRef)
		if err != nil {
			return nil, errors.Errorf("failed to get user %q: %w", req.UserRef, ErrFromRemote(resp, err))
		}

		curUserID := h.CurrentUserID(ctx)

		// user must be already logged in the create a linked account and can create a
		// linked account only on itself.
		if user.ID != curUserID {
			return nil, util.NewErrBadRequest(errors.Errorf("logged in user cannot create linked account for another user"))
		}

		var la *cstypes.LinkedAccount
		for _, v := range user.LinkedAccounts {
			if v.RemoteSourceID == rs.ID {
				la = v
				break
			}
		}
		if la != nil {
			return nil, util.NewErrBadRequest(errors.Errorf("user %q already have a linked account for remote source %q", req.UserRef, rs.Name))
		}

	case RemoteSourceRequestTypeLoginUser:

	case RemoteSourceRequestTypeAuthorize:

	case RemoteSourceRequestTypeRegisterUser:

	default:
		return nil, errors.Errorf("unknown request type: %q", requestType)
	}

	switch rs.AuthType {
	case cstypes.RemoteSourceAuthTypeOauth2:
		oauth2Source, err := common.GetOauth2Source(rs, "")
		if err != nil {
			return nil, errors.Errorf("failed to create git source: %w", err)
		}
		token, err := common.GenerateOauth2JWTToken(h.sd, rs.Name, string(requestType), req)
		if err != nil {
			return nil, err
		}
		redirect, err := oauth2Source.GetOauth2AuthorizationURL(h.webExposedURL+"/oauth2/callback", token)
		if err != nil {
			return nil, err
		}

		return &RemoteSourceAuthResponse{
			Oauth2Redirect: redirect,
		}, nil

	case cstypes.RemoteSourceAuthTypePassword:
		passwordSource, err := common.GetPasswordSource(rs, "")
		if err != nil {
			return nil, errors.Errorf("failed to create git source: %w", err)
		}
		tokenName := "agola-" + h.agolaID
		accessToken, err := passwordSource.LoginPassword(loginName, loginPassword, tokenName)
		if err != nil {
			if err == gitsource.ErrUnauthorized {
				return nil, util.NewErrUnauthorized(errors.Errorf("failed to login to remotesource %q: %w", remoteSourceName, err))
			}
			return nil, errors.Errorf("failed to login to remote source %q with login name %q: %w", rs.Name, loginName, err)
		}
		requestj, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		cres, err := h.HandleRemoteSourceAuthRequest(ctx, requestType, string(requestj), accessToken, "", "", time.Time{})
		if err != nil {
			return nil, err
		}
		return &RemoteSourceAuthResponse{
			Response: cres.Response,
		}, nil

	default:
		return nil, errors.Errorf("unknown remote source authentication type: %q", rs.AuthType)
	}
}

type RemoteSourceRequestType string

const (
	RemoteSourceRequestTypeCreateUserLA RemoteSourceRequestType = "createuserla"
	RemoteSourceRequestTypeLoginUser    RemoteSourceRequestType = "loginuser"
	RemoteSourceRequestTypeAuthorize    RemoteSourceRequestType = "authorize"
	RemoteSourceRequestTypeRegisterUser RemoteSourceRequestType = "registeruser"
)

type RemoteSourceAuthResult struct {
	RequestType RemoteSourceRequestType
	Response    interface{}
}

type CreateUserLAResponse struct {
	LinkedAccount *cstypes.LinkedAccount
}

func (h *ActionHandler) HandleRemoteSourceAuthRequest(ctx context.Context, requestType RemoteSourceRequestType, requestString string, userAccessToken, oauth2AccessToken, oauth2RefreshToken string, oauth2AccessTokenExpiresAt time.Time) (*RemoteSourceAuthResult, error) {
	switch requestType {
	case RemoteSourceRequestTypeCreateUserLA:
		var req *CreateUserLARequest
		if err := json.Unmarshal([]byte(requestString), &req); err != nil {
			return nil, errors.Errorf("failed to unmarshal request")
		}

		creq := &CreateUserLARequest{
			UserRef:                    req.UserRef,
			RemoteSourceName:           req.RemoteSourceName,
			UserAccessToken:            userAccessToken,
			Oauth2AccessToken:          oauth2AccessToken,
			Oauth2RefreshToken:         oauth2RefreshToken,
			Oauth2AccessTokenExpiresAt: oauth2AccessTokenExpiresAt,
		}
		la, err := h.CreateUserLA(ctx, creq)
		if err != nil {
			return nil, err
		}
		return &RemoteSourceAuthResult{
			RequestType: requestType,
			Response: &CreateUserLAResponse{
				LinkedAccount: la,
			},
		}, nil

	case RemoteSourceRequestTypeRegisterUser:
		var req *RegisterUserRequest
		if err := json.Unmarshal([]byte(requestString), &req); err != nil {
			return nil, errors.Errorf("failed to unmarshal request")
		}

		creq := &RegisterUserRequest{
			UserName:                   req.UserName,
			RemoteSourceName:           req.RemoteSourceName,
			UserAccessToken:            userAccessToken,
			Oauth2AccessToken:          oauth2AccessToken,
			Oauth2RefreshToken:         oauth2RefreshToken,
			Oauth2AccessTokenExpiresAt: oauth2AccessTokenExpiresAt,
		}
		cresp, err := h.RegisterUser(ctx, creq)
		if err != nil {
			return nil, err
		}
		return &RemoteSourceAuthResult{
			RequestType: requestType,
			Response:    cresp,
		}, nil

	case RemoteSourceRequestTypeLoginUser:
		var req *LoginUserRequest
		if err := json.Unmarshal([]byte(requestString), &req); err != nil {
			return nil, errors.Errorf("failed to unmarshal request")
		}

		creq := &LoginUserRequest{
			RemoteSourceName:           req.RemoteSourceName,
			UserAccessToken:            userAccessToken,
			Oauth2AccessToken:          oauth2AccessToken,
			Oauth2RefreshToken:         oauth2RefreshToken,
			Oauth2AccessTokenExpiresAt: oauth2AccessTokenExpiresAt,
		}
		cresp, err := h.LoginUser(ctx, creq)
		if err != nil {
			return nil, err
		}
		return &RemoteSourceAuthResult{
			RequestType: requestType,
			Response:    cresp,
		}, nil

	case RemoteSourceRequestTypeAuthorize:
		var req *AuthorizeRequest
		if err := json.Unmarshal([]byte(requestString), &req); err != nil {
			return nil, errors.Errorf("failed to unmarshal request")
		}

		creq := &AuthorizeRequest{
			RemoteSourceName:           req.RemoteSourceName,
			UserAccessToken:            userAccessToken,
			Oauth2AccessToken:          oauth2AccessToken,
			Oauth2RefreshToken:         oauth2RefreshToken,
			Oauth2AccessTokenExpiresAt: oauth2AccessTokenExpiresAt,
		}
		cresp, err := h.Authorize(ctx, creq)
		if err != nil {
			return nil, err
		}
		return &RemoteSourceAuthResult{
			RequestType: requestType,
			Response:    cresp,
		}, nil

	default:
		return nil, errors.Errorf("unknown request")
	}
}

func (h *ActionHandler) HandleOauth2Callback(ctx context.Context, code, state string) (*RemoteSourceAuthResult, error) {
	token, err := jwt.Parse(state, func(token *jwt.Token) (interface{}, error) {
		if token.Method != h.sd.Method {
			return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		var key interface{}
		switch h.sd.Method {
		case jwt.SigningMethodRS256:
			key = h.sd.PrivateKey
		case jwt.SigningMethodHS256:
			key = h.sd.Key
		default:
			return nil, errors.Errorf("unsupported signing method %q", h.sd.Method.Alg())
		}
		return key, nil
	})
	if err != nil {
		return nil, errors.Errorf("failed to parse jwt: %w", err)
	}
	if !token.Valid {
		return nil, errors.Errorf("invalid token")
	}

	claims := token.Claims.(jwt.MapClaims)
	remoteSourceName := claims["remote_source_name"].(string)
	requestType := RemoteSourceRequestType(claims["request_type"].(string))
	requestString := claims["request"].(string)

	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, remoteSourceName)
	if err != nil {
		return nil, errors.Errorf("failed to get remote source %q: %w", remoteSourceName, ErrFromRemote(resp, err))
	}

	oauth2Source, err := common.GetOauth2Source(rs, "")
	if err != nil {
		return nil, errors.Errorf("failed to create oauth2 source: %w", err)
	}

	oauth2Token, err := oauth2Source.RequestOauth2Token(h.webExposedURL+"/oauth2/callback", code)
	if err != nil {
		return nil, err
	}

	return h.HandleRemoteSourceAuthRequest(ctx, requestType, requestString, "", oauth2Token.AccessToken, oauth2Token.RefreshToken, oauth2Token.Expiry)
}

func (h *ActionHandler) DeleteUser(ctx context.Context, userRef string) error {
	if !h.IsUserAdmin(ctx) {
		return errors.Errorf("user not logged in")
	}

	resp, err := h.configstoreClient.DeleteUser(ctx, userRef)
	if err != nil {
		return errors.Errorf("failed to delete user: %w", ErrFromRemote(resp, err))
	}
	return nil
}

func (h *ActionHandler) DeleteUserLA(ctx context.Context, userRef, laID string) error {
	if !h.IsUserLoggedOrAdmin(ctx) {
		return errors.Errorf("user not logged in")
	}

	isAdmin := !h.IsUserAdmin(ctx)
	curUserID := h.CurrentUserID(ctx)

	user, resp, err := h.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return errors.Errorf("failed to get user %q: %w", userRef, ErrFromRemote(resp, err))
	}

	// only admin or the same logged user can create a token
	if !isAdmin && user.ID != curUserID {
		return util.NewErrBadRequest(errors.Errorf("logged in user cannot create token for another user"))
	}

	resp, err = h.configstoreClient.DeleteUserLA(ctx, userRef, laID)
	if err != nil {
		return errors.Errorf("failed to delete user linked account: %w", ErrFromRemote(resp, err))
	}
	return nil
}

func (h *ActionHandler) DeleteUserToken(ctx context.Context, userRef, tokenName string) error {
	if !h.IsUserLoggedOrAdmin(ctx) {
		return errors.Errorf("user not logged in")
	}

	isAdmin := !h.IsUserAdmin(ctx)
	curUserID := h.CurrentUserID(ctx)

	user, resp, err := h.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return errors.Errorf("failed to get user %q: %w", userRef, ErrFromRemote(resp, err))
	}

	// only admin or the same logged user can create a token
	if !isAdmin && user.ID != curUserID {
		return util.NewErrBadRequest(errors.Errorf("logged in user cannot delete token for another user"))
	}

	resp, err = h.configstoreClient.DeleteUserToken(ctx, userRef, tokenName)
	if err != nil {
		return errors.Errorf("failed to delete user token: %w", ErrFromRemote(resp, err))
	}
	return nil
}

type UserCreateRunRequest struct {
	RepoUUID  string
	RepoPath  string
	Branch    string
	Tag       string
	Ref       string
	CommitSHA string
	Message   string

	PullRequestRefRegexes []string
	Variables             map[string]string
}

func (h *ActionHandler) UserCreateRun(ctx context.Context, req *UserCreateRunRequest) error {
	prRefRegexes := []*regexp.Regexp{}
	for _, res := range req.PullRequestRefRegexes {
		re, err := regexp.Compile(res)
		if err != nil {
			return fmt.Errorf("wrong regular expression %q: %v", res, err)
		}
		prRefRegexes = append(prRefRegexes, re)
	}

	curUserID := h.CurrentUserID(ctx)

	user, resp, err := h.configstoreClient.GetUser(ctx, curUserID)
	if err != nil {
		return errors.Errorf("failed to get user %q: %w", curUserID, ErrFromRemote(resp, err))
	}

	// Verify that the repo is owned by the user
	repoParts := strings.Split(req.RepoPath, "/")
	if req.RepoUUID == "" {
		return util.NewErrBadRequest(errors.Errorf("empty repo uuid"))
	}
	if len(repoParts) != 2 {
		return util.NewErrBadRequest(errors.Errorf("wrong repo path: %q", req.RepoPath))
	}
	if repoParts[0] != user.ID {
		return util.NewErrUnauthorized(errors.Errorf("repo %q not owned", req.RepoPath))
	}

	branch := req.Branch
	tag := req.Tag
	ref := req.Ref

	set := 0
	if branch != "" {
		set++
	}
	if tag != "" {
		set++
	}
	if ref != "" {
		set++
	}
	if set == 0 {
		return util.NewErrBadRequest(errors.Errorf("one of branch, tag or ref is required"))
	}
	if set > 1 {
		return util.NewErrBadRequest(errors.Errorf("only one of branch, tag or ref can be provided"))
	}

	gitSource := agolagit.New(h.apiExposedURL+"/repos", prRefRegexes)
	cloneURL := fmt.Sprintf("%s/%s.git", h.apiExposedURL+"/repos", req.RepoPath)

	if ref == "" {
		if branch != "" {
			ref = gitSource.BranchRef(branch)
		}
		if tag != "" {
			ref = gitSource.TagRef(tag)
		}
	}

	gitRefType, name, err := gitSource.RefType(ref)
	if err != nil {
		return util.NewErrBadRequest(errors.Errorf("failed to get refType for ref %q: %w", ref, err))
	}

	var pullRequestID string

	switch gitRefType {
	case gitsource.RefTypeBranch:
		branch = name
	case gitsource.RefTypeTag:
		tag = name
	case gitsource.RefTypePullRequest:
		pullRequestID = name
	default:
		return errors.Errorf("unsupported ref %q for manual run creation", ref)
	}

	var refType types.RunRefType

	if branch != "" {
		refType = types.RunRefTypeBranch
	}
	if tag != "" {
		refType = types.RunRefTypeTag
	}
	if pullRequestID != "" {
		refType = types.RunRefTypePullRequest
	}

	creq := &CreateRunRequest{
		RunType:            types.RunTypeUser,
		RefType:            refType,
		RunCreationTrigger: types.RunCreationTriggerTypeManual,

		Project:       nil,
		User:          user,
		RepoPath:      req.RepoPath,
		GitSource:     gitSource,
		CommitSHA:     req.CommitSHA,
		Message:       req.Message,
		Branch:        branch,
		Tag:           tag,
		Ref:           ref,
		PullRequestID: pullRequestID,
		CloneURL:      cloneURL,

		CommitLink:      "",
		BranchLink:      "",
		TagLink:         "",
		PullRequestLink: "",

		UserRunRepoUUID: req.RepoUUID,
		Variables:       req.Variables,
	}

	return h.CreateRuns(ctx, creq)
}
