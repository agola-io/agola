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

	"agola.io/agola/internal/errors"
	gitsource "agola.io/agola/internal/gitsources"
	"agola.io/agola/internal/gitsources/agolagit"
	scommon "agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/services/types"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"

	"github.com/golang-jwt/jwt/v4"
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

func (h *ActionHandler) GetCurrentUser(ctx context.Context, userRef string) (*cstypes.User, []*cstypes.UserToken, []*cstypes.LinkedAccount, error) {
	if !common.IsUserLoggedOrAdmin(ctx) {
		return nil, nil, nil, errors.Errorf("user not logged in")
	}

	user, _, err := h.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return nil, nil, nil, util.NewAPIError(util.KindFromRemoteError(err), err)
	}

	tokens, _, err := h.configstoreClient.GetUserTokens(ctx, user.ID)
	if err != nil {
		return nil, nil, nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user %q tokens", user.ID))
	}

	linkedAccounts, _, err := h.configstoreClient.GetUserLinkedAccounts(ctx, user.ID)
	if err != nil {
		return nil, nil, nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user %q linked accounts", user.ID))
	}

	return user, tokens, linkedAccounts, nil
}

func (h *ActionHandler) GetUser(ctx context.Context, userRef string) (*cstypes.User, error) {
	if !common.IsUserLoggedOrAdmin(ctx) {
		return nil, errors.Errorf("user not logged in")
	}

	user, _, err := h.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
	}
	return user, nil
}

func (h *ActionHandler) GetUserOrgs(ctx context.Context, userRef string) ([]*csapitypes.UserOrgsResponse, error) {
	if !common.IsUserLogged(ctx) {
		return nil, errors.Errorf("user not logged in")
	}

	orgs, _, err := h.configstoreClient.GetUserOrgs(ctx, userRef)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
	}
	return orgs, nil
}

type GetUsersRequest struct {
	Start string
	Limit int
	Asc   bool
}

func (h *ActionHandler) GetUsers(ctx context.Context, req *GetUsersRequest) ([]*cstypes.User, error) {
	if !common.IsUserAdmin(ctx) {
		return nil, errors.Errorf("user not logged in")
	}

	users, _, err := h.configstoreClient.GetUsers(ctx, req.Start, req.Limit, req.Asc)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
	}
	return users, nil
}

type CreateUserRequest struct {
	UserName string
}

func (h *ActionHandler) CreateUser(ctx context.Context, req *CreateUserRequest) (*cstypes.User, error) {
	if !common.IsUserAdmin(ctx) {
		return nil, errors.Errorf("user not admin")
	}

	if req.UserName == "" {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("user name required"))
	}
	if !util.ValidateName(req.UserName) {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid user name %q", req.UserName))
	}

	creq := &csapitypes.CreateUserRequest{
		UserName: req.UserName,
	}

	h.log.Info().Msgf("creating user")
	u, _, err := h.configstoreClient.CreateUser(ctx, creq)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to create user"))
	}
	h.log.Info().Msgf("user %s created, ID: %s", u.Name, u.ID)

	return u, nil
}

type CreateUserTokenRequest struct {
	UserRef   string
	TokenName string
}

func (h *ActionHandler) CreateUserToken(ctx context.Context, req *CreateUserTokenRequest) (string, error) {
	isAdmin := common.IsUserAdmin(ctx)
	userID := common.CurrentUserID(ctx)

	userRef := req.UserRef
	user, _, err := h.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return "", util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user"))
	}

	// only admin or the same logged user can create a token
	if !isAdmin && user.ID != userID {
		return "", util.NewAPIError(util.ErrBadRequest, errors.Errorf("logged in user cannot create token for another user"))
	}

	tokens, _, err := h.configstoreClient.GetUserTokens(ctx, user.ID)
	if err != nil {
		return "", util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user %q tokens", user.ID))
	}

	var token *cstypes.UserToken
	for _, v := range tokens {
		if v.Name == req.TokenName {
			token = v
			break
		}
	}
	if token != nil {
		return "", util.NewAPIError(util.ErrBadRequest, errors.Errorf("user %q already have a token with name %q", userRef, req.TokenName))
	}

	h.log.Info().Msgf("creating user token")
	creq := &csapitypes.CreateUserTokenRequest{
		TokenName: req.TokenName,
	}
	res, _, err := h.configstoreClient.CreateUserToken(ctx, userRef, creq)
	if err != nil {
		return "", util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to create user token"))
	}
	h.log.Info().Msgf("token %q for user %q created", req.TokenName, userRef)

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
	rs, _, err := h.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get remote source %q", req.RemoteSourceName))
	}
	linkedAccounts, _, err := h.configstoreClient.GetUserLinkedAccounts(ctx, userRef)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user %q linked accounts", userRef))
	}

	var la *cstypes.LinkedAccount
	for _, v := range linkedAccounts {
		if v.RemoteSourceID == rs.ID {
			la = v
			break
		}
	}
	if la != nil {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("user %q already have a linked account for remote source %q", userRef, rs.Name))
	}

	accessToken, err := scommon.GetAccessToken(rs, req.UserAccessToken, req.Oauth2AccessToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	userSource, err := scommon.GetUserSource(rs, accessToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	remoteUserInfo, err := userSource.GetUserInfo()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve remote user info for remote source %q", rs.ID)
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

	h.log.Info().Msgf("creating linked account")
	la, _, err = h.configstoreClient.CreateUserLA(ctx, userRef, creq)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to create linked account"))
	}
	h.log.Info().Msgf("linked account %q for user %q created", la.ID, userRef)

	return la, nil
}

func (h *ActionHandler) UpdateUserLA(ctx context.Context, userRef string, la *cstypes.LinkedAccount) error {
	linkedAccounts, _, err := h.configstoreClient.GetUserLinkedAccounts(ctx, userRef)
	if err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user %q linked accounts", userRef))
	}

	laFound := false
	for _, ula := range linkedAccounts {
		if ula.ID == la.ID {
			laFound = true
			break
		}
	}
	if !laFound {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("user %q doesn't have a linked account with id %q", userRef, la.ID))
	}

	creq := &csapitypes.UpdateUserLARequest{
		RemoteUserID:               la.RemoteUserID,
		RemoteUserName:             la.RemoteUserName,
		UserAccessToken:            la.UserAccessToken,
		Oauth2AccessToken:          la.Oauth2AccessToken,
		Oauth2RefreshToken:         la.Oauth2RefreshToken,
		Oauth2AccessTokenExpiresAt: la.Oauth2AccessTokenExpiresAt,
	}

	h.log.Info().Msgf("updating user %q linked account", userRef)
	la, _, err = h.configstoreClient.UpdateUserLA(ctx, userRef, la.ID, creq)
	if err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to update user"))
	}
	h.log.Info().Msgf("linked account %q for user %q updated", la.ID, userRef)

	return nil
}

// RefreshLinkedAccount refreshed the linked account oauth2 access token and update linked account in the configstore
func (h *ActionHandler) RefreshLinkedAccount(ctx context.Context, rs *cstypes.RemoteSource, userName string, la *cstypes.LinkedAccount) (*cstypes.LinkedAccount, error) {
	switch rs.AuthType {
	case cstypes.RemoteSourceAuthTypeOauth2:
		// refresh access token if expired
		if isAccessTokenExpired(la.Oauth2AccessTokenExpiresAt) {
			userSource, err := scommon.GetOauth2Source(rs, "")
			if err != nil {
				return nil, errors.WithStack(err)
			}
			token, err := userSource.RefreshOauth2Token(la.Oauth2RefreshToken)
			if err != nil {
				return nil, errors.WithStack(err)
			}

			if la.Oauth2AccessToken != token.AccessToken {
				la.Oauth2AccessToken = token.AccessToken
				la.Oauth2RefreshToken = token.RefreshToken
				la.Oauth2AccessTokenExpiresAt = token.Expiry

				if err := h.UpdateUserLA(ctx, userName, la); err != nil {
					return nil, errors.Wrapf(err, "failed to update linked account")
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
		return nil, errors.WithStack(err)
	}
	gs, err := scommon.GetGitSource(rs, la)
	return gs, errors.WithStack(err)
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
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("user name required"))
	}
	if !util.ValidateName(req.UserName) {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid user name %q", req.UserName))
	}

	rs, _, err := h.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get remote source %q", req.RemoteSourceName))
	}
	if !*rs.RegistrationEnabled {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("remote source user registration is disabled"))
	}

	accessToken, err := scommon.GetAccessToken(rs, req.UserAccessToken, req.Oauth2AccessToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	userSource, err := scommon.GetUserSource(rs, accessToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	remoteUserInfo, err := userSource.GetUserInfo()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve remote user info for remote source %q", rs.ID)
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

	h.log.Info().Msgf("creating user account")
	u, _, err := h.configstoreClient.CreateUser(ctx, creq)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to create linked account"))
	}
	h.log.Info().Msgf("user %q created", req.UserName)

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
	rs, _, err := h.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get remote source %q", req.RemoteSourceName))
	}
	if !*rs.LoginEnabled {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("remote source user login is disabled"))
	}

	accessToken, err := scommon.GetAccessToken(rs, req.UserAccessToken, req.Oauth2AccessToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	userSource, err := scommon.GetUserSource(rs, accessToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	remoteUserInfo, err := userSource.GetUserInfo()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve remote user info for remote source %q", rs.ID)
	}
	if remoteUserInfo.ID == "" {
		return nil, errors.Errorf("empty remote user id for remote source %q", rs.ID)
	}

	user, _, err := h.configstoreClient.GetUserByLinkedAccountRemoteUserAndSource(ctx, remoteUserInfo.ID, rs.ID)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user for remote user id %q and remote source %q", remoteUserInfo.ID, rs.ID))
	}

	linkedAccounts, _, err := h.configstoreClient.GetUserLinkedAccounts(ctx, user.ID)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user %q linked accounts", user.ID))
	}

	var la *cstypes.LinkedAccount
	for _, v := range linkedAccounts {
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

		h.log.Info().Msgf("updating user %q linked account", user.Name)
		la, _, err = h.configstoreClient.UpdateUserLA(ctx, user.Name, la.ID, creq)
		if err != nil {
			return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to update user"))
		}
		h.log.Info().Msgf("linked account %q for user %q updated", la.ID, user.Name)
	}

	// generate jwt token
	token, err := scommon.GenerateLoginJWTToken(h.sd, user.ID)
	if err != nil {
		return nil, errors.WithStack(err)
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
	rs, _, err := h.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get remote source %q", req.RemoteSourceName))
	}

	accessToken, err := scommon.GetAccessToken(rs, req.UserAccessToken, req.Oauth2AccessToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	userSource, err := scommon.GetUserSource(rs, accessToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	remoteUserInfo, err := userSource.GetUserInfo()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve remote user info for remote source %q", rs.ID)
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
	rs, _, err := h.configstoreClient.GetRemoteSource(ctx, remoteSourceName)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get remote source %q", remoteSourceName))
	}

	switch requestType {
	case RemoteSourceRequestTypeCreateUserLA:
		req := req.(*CreateUserLARequest)

		user, _, err := h.configstoreClient.GetUser(ctx, req.UserRef)
		if err != nil {
			return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user %q", req.UserRef))
		}

		curUserID := common.CurrentUserID(ctx)

		// user must be already logged in the create a linked account and can create a
		// linked account only on itself.
		if user.ID != curUserID {
			return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("logged in user cannot create linked account for another user"))
		}

		linkedAccounts, _, err := h.configstoreClient.GetUserLinkedAccounts(ctx, user.ID)
		if err != nil {
			return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user %q linked accounts", user.ID))
		}

		var la *cstypes.LinkedAccount
		for _, v := range linkedAccounts {
			if v.RemoteSourceID == rs.ID {
				la = v
				break
			}
		}
		if la != nil {
			return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("user %q already have a linked account for remote source %q", req.UserRef, rs.Name))
		}

	case RemoteSourceRequestTypeLoginUser:

	case RemoteSourceRequestTypeAuthorize:

	case RemoteSourceRequestTypeRegisterUser:

	default:
		return nil, errors.Errorf("unknown request type: %q", requestType)
	}

	switch rs.AuthType {
	case cstypes.RemoteSourceAuthTypeOauth2:
		oauth2Source, err := scommon.GetOauth2Source(rs, "")
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create git source")
		}
		token, err := scommon.GenerateOauth2JWTToken(h.sd, rs.Name, string(requestType), req)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		redirect, err := oauth2Source.GetOauth2AuthorizationURL(h.webExposedURL+"/oauth2/callback", token)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		return &RemoteSourceAuthResponse{
			Oauth2Redirect: redirect,
		}, nil

	case cstypes.RemoteSourceAuthTypePassword:
		passwordSource, err := scommon.GetPasswordSource(rs, "")
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create git source")
		}
		tokenName := "agola-" + h.agolaID
		accessToken, err := passwordSource.LoginPassword(loginName, loginPassword, tokenName)
		if err != nil {
			if errors.Is(err, gitsource.ErrUnauthorized) {
				return nil, util.NewAPIError(util.ErrUnauthorized, errors.Wrapf(err, "failed to login to remotesource %q", remoteSourceName))
			}
			return nil, errors.Wrapf(err, "failed to login to remote source %q with login name %q", rs.Name, loginName)
		}
		requestj, err := json.Marshal(req)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		cres, err := h.HandleRemoteSourceAuthRequest(ctx, requestType, string(requestj), accessToken, "", "", time.Time{})
		if err != nil {
			return nil, errors.WithStack(err)
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
			return nil, errors.WithStack(err)
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
			return nil, errors.WithStack(err)
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
			return nil, errors.WithStack(err)
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
			return nil, errors.WithStack(err)
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
		return nil, errors.Wrapf(err, "failed to parse jwt")
	}
	if !token.Valid {
		return nil, errors.Errorf("invalid token")
	}

	claims := token.Claims.(jwt.MapClaims)
	remoteSourceName := claims["remote_source_name"].(string)
	requestType := RemoteSourceRequestType(claims["request_type"].(string))
	requestString := claims["request"].(string)

	rs, _, err := h.configstoreClient.GetRemoteSource(ctx, remoteSourceName)
	if err != nil {
		return nil, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get remote source %q", remoteSourceName))
	}

	oauth2Source, err := scommon.GetOauth2Source(rs, "")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create oauth2 source")
	}

	oauth2Token, err := oauth2Source.RequestOauth2Token(h.webExposedURL+"/oauth2/callback", code)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return h.HandleRemoteSourceAuthRequest(ctx, requestType, requestString, "", oauth2Token.AccessToken, oauth2Token.RefreshToken, oauth2Token.Expiry)
}

func (h *ActionHandler) DeleteUser(ctx context.Context, userRef string) error {
	if !common.IsUserAdmin(ctx) {
		return errors.Errorf("user not logged in")
	}

	if _, err := h.configstoreClient.DeleteUser(ctx, userRef); err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to delete user"))
	}
	return nil
}

func (h *ActionHandler) DeleteUserLA(ctx context.Context, userRef, laID string) error {
	if !common.IsUserLoggedOrAdmin(ctx) {
		return errors.Errorf("user not logged in")
	}

	isAdmin := common.IsUserAdmin(ctx)
	curUserID := common.CurrentUserID(ctx)

	user, _, err := h.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user %q", userRef))
	}

	// only admin or the same logged user can create a token
	if !isAdmin && user.ID != curUserID {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("logged in user cannot create token for another user"))
	}

	if _, err = h.configstoreClient.DeleteUserLA(ctx, userRef, laID); err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to delete user linked account"))
	}
	return nil
}

func (h *ActionHandler) DeleteUserToken(ctx context.Context, userRef, tokenName string) error {
	if !common.IsUserLoggedOrAdmin(ctx) {
		return errors.Errorf("user not logged in")
	}

	isAdmin := common.IsUserAdmin(ctx)
	curUserID := common.CurrentUserID(ctx)

	user, _, err := h.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user %q", userRef))
	}

	// only admin or the same logged user can create a token
	if !isAdmin && user.ID != curUserID {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("logged in user cannot delete token for another user"))
	}

	if _, err = h.configstoreClient.DeleteUserToken(ctx, userRef, tokenName); err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to delete user token"))
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
			return errors.Wrapf(err, "wrong regular expression %q", res)
		}
		prRefRegexes = append(prRefRegexes, re)
	}

	curUserID := common.CurrentUserID(ctx)

	user, _, err := h.configstoreClient.GetUser(ctx, curUserID)
	if err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user %q", curUserID))
	}

	// Verify that the repo is owned by the user
	repoParts := strings.Split(req.RepoPath, "/")
	if req.RepoUUID == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("empty repo uuid"))
	}
	if len(repoParts) != 2 {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("wrong repo path: %q", req.RepoPath))
	}
	if repoParts[0] != user.ID {
		return util.NewAPIError(util.ErrUnauthorized, errors.Errorf("repo %q not owned", req.RepoPath))
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
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("one of branch, tag or ref is required"))
	}
	if set > 1 {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("only one of branch, tag or ref can be provided"))
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
		return util.NewAPIError(util.ErrBadRequest, errors.Wrapf(err, "failed to get refType for ref %q", ref))
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
