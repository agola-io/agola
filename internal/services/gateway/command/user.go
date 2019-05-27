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

package command

import (
	"context"
	"encoding/json"
	"time"

	gitsource "github.com/sorintlab/agola/internal/gitsources"
	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/common"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
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

type CreateUserRequest struct {
	UserName string
}

func (c *CommandHandler) CreateUser(ctx context.Context, req *CreateUserRequest) (*types.User, error) {
	if req.UserName == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("user name required"))
	}
	if !util.ValidateName(req.UserName) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid user name %q", req.UserName))
	}

	creq := &csapi.CreateUserRequest{
		UserName: req.UserName,
	}

	c.log.Infof("creating user")
	u, resp, err := c.configstoreClient.CreateUser(ctx, creq)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to create user"))
	}
	c.log.Infof("user %s created, ID: %s", u.Name, u.ID)

	return u, nil
}

type CreateUserTokenRequest struct {
	UserRef   string
	TokenName string
}

func (c *CommandHandler) CreateUserToken(ctx context.Context, req *CreateUserTokenRequest) (string, error) {
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
	user, resp, err := c.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return "", ErrFromRemote(resp, errors.Wrapf(err, "failed to get user"))
	}

	// only admin or the same logged user can create a token
	if !isAdmin && user.ID != userID {
		return "", util.NewErrBadRequest(errors.Errorf("logged in user cannot create token for another user"))
	}
	if _, ok := user.Tokens[req.TokenName]; ok {
		return "", util.NewErrBadRequest(errors.Errorf("user %q already have a token with name %q", userRef, req.TokenName))
	}

	c.log.Infof("creating user token")
	creq := &csapi.CreateUserTokenRequest{
		TokenName: req.TokenName,
	}
	res, resp, err := c.configstoreClient.CreateUserToken(ctx, userRef, creq)
	if err != nil {
		return "", ErrFromRemote(resp, errors.Wrapf(err, "failed to create user token"))
	}
	c.log.Infof("token %q for user %q created", req.TokenName, userRef)

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

func (c *CommandHandler) CreateUserLA(ctx context.Context, req *CreateUserLARequest) (*types.LinkedAccount, error) {
	userRef := req.UserRef
	user, resp, err := c.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to get user %q", userRef))
	}
	rs, resp, err := c.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to get remote source %q", req.RemoteSourceName))
	}
	c.log.Infof("rs: %s", util.Dump(rs))
	var la *types.LinkedAccount
	for _, v := range user.LinkedAccounts {
		if v.RemoteSourceID == rs.ID {
			la = v
			break
		}
	}
	c.log.Infof("la: %s", util.Dump(la))
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
		return nil, errors.Wrapf(err, "failed to retrieve remote user info for remote source %q", rs.ID)
	}
	if remoteUserInfo.ID == "" {
		return nil, errors.Errorf("empty remote user id for remote source %q", rs.ID)
	}

	creq := &csapi.CreateUserLARequest{
		RemoteSourceName:           req.RemoteSourceName,
		RemoteUserID:               remoteUserInfo.ID,
		RemoteUserName:             remoteUserInfo.LoginName,
		UserAccessToken:            req.UserAccessToken,
		Oauth2AccessToken:          req.Oauth2AccessToken,
		Oauth2RefreshToken:         req.Oauth2RefreshToken,
		Oauth2AccessTokenExpiresAt: req.Oauth2AccessTokenExpiresAt,
	}

	c.log.Infof("creating linked account")
	la, resp, err = c.configstoreClient.CreateUserLA(ctx, userRef, creq)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to create linked account"))
	}
	c.log.Infof("linked account %q for user %q created", la.ID, userRef)

	return la, nil
}

func (c *CommandHandler) UpdateUserLA(ctx context.Context, userRef string, la *types.LinkedAccount) error {
	user, resp, err := c.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return ErrFromRemote(resp, errors.Wrapf(err, "failed to get user %q", userRef))
	}
	laFound := false
	for _, ula := range user.LinkedAccounts {
		if ula.ID == la.ID {
			laFound = true
			break
		}
	}
	c.log.Infof("la: %s", util.Dump(la))
	if !laFound {
		return util.NewErrBadRequest(errors.Errorf("user %q doesn't have a linked account with id %q", userRef, la.ID))
	}

	creq := &csapi.UpdateUserLARequest{
		RemoteUserID:               la.RemoteUserID,
		RemoteUserName:             la.RemoteUserName,
		UserAccessToken:            la.UserAccessToken,
		Oauth2AccessToken:          la.Oauth2AccessToken,
		Oauth2RefreshToken:         la.Oauth2RefreshToken,
		Oauth2AccessTokenExpiresAt: la.Oauth2AccessTokenExpiresAt,
	}

	c.log.Infof("updating user %q linked account", userRef)
	la, resp, err = c.configstoreClient.UpdateUserLA(ctx, userRef, la.ID, creq)
	if err != nil {
		return ErrFromRemote(resp, errors.Wrapf(err, "failed to update user"))
	}
	c.log.Infof("linked account %q for user %q updated", la.ID, userRef)

	return nil
}

// RefreshLinkedAccount refreshed the linked account oauth2 access token and update linked account in the configstore
func (c *CommandHandler) RefreshLinkedAccount(ctx context.Context, rs *types.RemoteSource, userName string, la *types.LinkedAccount) (*types.LinkedAccount, error) {
	switch rs.AuthType {
	case types.RemoteSourceAuthTypeOauth2:
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

				if err := c.UpdateUserLA(ctx, userName, la); err != nil {
					return nil, errors.Wrapf(err, "failed to update linked account")
				}
			}
		}
	}
	return la, nil
}

// GetGitSource is a wrapper around common.GetGitSource that will also refresh
// the oauth2 access token and update the linked account when needed
func (c *CommandHandler) GetGitSource(ctx context.Context, rs *types.RemoteSource, userName string, la *types.LinkedAccount) (gitsource.GitSource, error) {
	la, err := c.RefreshLinkedAccount(ctx, rs, userName, la)
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

func (c *CommandHandler) RegisterUser(ctx context.Context, req *RegisterUserRequest) (*types.User, error) {
	if req.UserName == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("user name required"))
	}
	if !util.ValidateName(req.UserName) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid user name %q", req.UserName))
	}

	rs, resp, err := c.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to get remote source %q", req.RemoteSourceName))
	}
	c.log.Infof("rs: %s", util.Dump(rs))

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
		return nil, errors.Wrapf(err, "failed to retrieve remote user info for remote source %q", rs.ID)
	}
	if remoteUserInfo.ID == "" {
		return nil, errors.Errorf("empty remote user id for remote source %q", rs.ID)
	}

	creq := &csapi.CreateUserRequest{
		UserName: req.UserName,
		CreateUserLARequest: &csapi.CreateUserLARequest{
			RemoteSourceName:           req.RemoteSourceName,
			RemoteUserID:               remoteUserInfo.ID,
			RemoteUserName:             remoteUserInfo.LoginName,
			UserAccessToken:            req.UserAccessToken,
			Oauth2AccessToken:          req.Oauth2AccessToken,
			Oauth2RefreshToken:         req.Oauth2RefreshToken,
			Oauth2AccessTokenExpiresAt: req.Oauth2AccessTokenExpiresAt,
		},
	}

	c.log.Infof("creating user account")
	u, resp, err := c.configstoreClient.CreateUser(ctx, creq)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to create linked account"))
	}
	c.log.Infof("user %q created", req.UserName)

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
	User  *types.User
}

func (c *CommandHandler) LoginUser(ctx context.Context, req *LoginUserRequest) (*LoginUserResponse, error) {
	rs, resp, err := c.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to get remote source %q", req.RemoteSourceName))
	}
	c.log.Infof("rs: %s", util.Dump(rs))

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
		return nil, errors.Wrapf(err, "failed to retrieve remote user info for remote source %q", rs.ID)
	}
	if remoteUserInfo.ID == "" {
		return nil, errors.Errorf("empty remote user id for remote source %q", rs.ID)
	}

	user, resp, err := c.configstoreClient.GetUserByLinkedAccountRemoteUserAndSource(ctx, remoteUserInfo.ID, rs.ID)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to get user for remote user id %q and remote source %q", remoteUserInfo.ID, rs.ID))
	}

	var la *types.LinkedAccount
	for _, v := range user.LinkedAccounts {
		if v.RemoteSourceID == rs.ID {
			la = v
			break
		}
	}
	c.log.Infof("la: %s", util.Dump(la))
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

		creq := &csapi.UpdateUserLARequest{
			RemoteUserID:               la.RemoteUserID,
			RemoteUserName:             la.RemoteUserName,
			UserAccessToken:            la.UserAccessToken,
			Oauth2AccessToken:          la.Oauth2AccessToken,
			Oauth2RefreshToken:         la.Oauth2RefreshToken,
			Oauth2AccessTokenExpiresAt: la.Oauth2AccessTokenExpiresAt,
		}

		c.log.Infof("updating user %q linked account", user.Name)
		la, resp, err = c.configstoreClient.UpdateUserLA(ctx, user.Name, la.ID, creq)
		if err != nil {
			return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to update user"))
		}
		c.log.Infof("linked account %q for user %q updated", la.ID, user.Name)
	}

	// generate jwt token
	token, err := common.GenerateLoginJWTToken(c.sd, user.ID)
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

func (c *CommandHandler) Authorize(ctx context.Context, req *AuthorizeRequest) (*AuthorizeResponse, error) {
	rs, resp, err := c.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to get remote source %q", req.RemoteSourceName))
	}
	c.log.Infof("rs: %s", util.Dump(rs))

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

func (c *CommandHandler) HandleRemoteSourceAuth(ctx context.Context, remoteSourceName, loginName, loginPassword string, requestType RemoteSourceRequestType, req interface{}) (*RemoteSourceAuthResponse, error) {
	rs, resp, err := c.configstoreClient.GetRemoteSource(ctx, remoteSourceName)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to get remote source %q", remoteSourceName))
	}
	c.log.Infof("rs: %s", util.Dump(rs))

	switch requestType {
	case RemoteSourceRequestTypeCreateUserLA:
		req := req.(*CreateUserLARequest)
		user, resp, err := c.configstoreClient.GetUser(ctx, req.UserRef)
		if err != nil {
			return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to get user %q", req.UserRef))
		}
		var la *types.LinkedAccount
		for _, v := range user.LinkedAccounts {
			if v.RemoteSourceID == rs.ID {
				la = v
				break
			}
		}
		c.log.Infof("la: %s", util.Dump(la))
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
	case types.RemoteSourceAuthTypeOauth2:
		oauth2Source, err := common.GetOauth2Source(rs, "")
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create git source")
		}
		token, err := common.GenerateJWTToken(c.sd, rs.Name, string(requestType), req)
		if err != nil {
			return nil, err
		}
		redirect, err := oauth2Source.GetOauth2AuthorizationURL(c.webExposedURL+"/oauth2/callback", token)
		if err != nil {
			return nil, err
		}
		c.log.Infof("oauth2 redirect: %s", redirect)

		return &RemoteSourceAuthResponse{
			Oauth2Redirect: redirect,
		}, nil

	case types.RemoteSourceAuthTypePassword:
		passwordSource, err := common.GetPasswordSource(rs, "")
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create git source")
		}
		tokenName := "agola-" + c.agolaID
		accessToken, err := passwordSource.LoginPassword(loginName, loginPassword, tokenName)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to login to remote source %q with login name %q", rs.Name, loginName)
		}
		c.log.Infof("access token: %s", accessToken)
		requestj, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		cres, err := c.HandleRemoteSourceAuthRequest(ctx, requestType, string(requestj), accessToken, "", "", time.Time{})
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
	LinkedAccount *types.LinkedAccount
}

func (c *CommandHandler) HandleRemoteSourceAuthRequest(ctx context.Context, requestType RemoteSourceRequestType, requestString string, userAccessToken, oauth2AccessToken, oauth2RefreshToken string, oauth2AccessTokenExpiresAt time.Time) (*RemoteSourceAuthResult, error) {
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
		la, err := c.CreateUserLA(ctx, creq)
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
		cresp, err := c.RegisterUser(ctx, creq)
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
		cresp, err := c.LoginUser(ctx, creq)
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
		cresp, err := c.Authorize(ctx, creq)
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

func (c *CommandHandler) HandleOauth2Callback(ctx context.Context, code, state string) (*RemoteSourceAuthResult, error) {
	token, err := jwt.Parse(state, func(token *jwt.Token) (interface{}, error) {
		if token.Method != c.sd.Method {
			return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		var key interface{}
		switch c.sd.Method {
		case jwt.SigningMethodRS256:
			key = c.sd.PrivateKey
		case jwt.SigningMethodHS256:
			key = c.sd.Key
		default:
			return nil, errors.Errorf("unsupported signing method %q", c.sd.Method.Alg())
		}
		return key, nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse jwt")
	}
	if !token.Valid {
		return nil, errors.Errorf("invalid token")
	}

	claims := token.Claims.(jwt.MapClaims)
	remoteSourceName := claims["remote_source_name"].(string)
	requestType := RemoteSourceRequestType(claims["request_type"].(string))
	requestString := claims["request"].(string)

	rs, resp, err := c.configstoreClient.GetRemoteSource(ctx, remoteSourceName)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to get remote source %q", remoteSourceName))
	}
	c.log.Infof("rs: %s", util.Dump(rs))

	oauth2Source, err := common.GetOauth2Source(rs, "")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create gitlab source")
	}

	oauth2Token, err := oauth2Source.RequestOauth2Token(c.webExposedURL+"/oauth2/callback", code)
	if err != nil {
		return nil, err
	}

	return c.HandleRemoteSourceAuthRequest(ctx, requestType, requestString, "", oauth2Token.AccessToken, oauth2Token.RefreshToken, oauth2Token.Expiry)
}
