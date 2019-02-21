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

package command

import (
	"context"
	"encoding/json"

	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/gateway/common"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

type CreateUserLARequest struct {
	UserName                       string
	RemoteSourceName               string
	RemoteSourceUserAccessToken    string
	RemoteSourceOauth2AccessToken  string
	RemoteSourceOauth2RefreshToken string
}

func (c *CommandHandler) CreateUserLA(ctx context.Context, req *CreateUserLARequest) (*types.LinkedAccount, error) {
	userName := req.UserName
	user, _, err := c.configstoreClient.GetUserByName(ctx, userName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user %q", userName)
	}
	rs, _, err := c.configstoreClient.GetRemoteSourceByName(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get remote source %q", req.RemoteSourceName)
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
		return nil, errors.Errorf("user %q already have a linked account for remote source %q", userName, rs.Name)
	}

	accessToken, err := common.GetAccessToken(rs.AuthType, req.RemoteSourceUserAccessToken, req.RemoteSourceOauth2AccessToken)
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
		RemoteSourceName:   req.RemoteSourceName,
		RemoteUserID:       remoteUserInfo.ID,
		RemoteUserName:     remoteUserInfo.LoginName,
		Oauth2AccessToken:  req.RemoteSourceOauth2AccessToken,
		Oauth2RefreshToken: req.RemoteSourceOauth2RefreshToken,
		UserAccessToken:    req.RemoteSourceUserAccessToken,
	}

	c.log.Infof("creating linked account")
	la, _, err = c.configstoreClient.CreateUserLA(ctx, userName, creq)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create linked account")
	}
	c.log.Infof("linked account %q for user %q created", la.ID, userName)

	return la, nil
}

type LoginUserRequest struct {
	RemoteSourceName               string
	RemoteSourceUserAccessToken    string
	RemoteSourceOauth2AccessToken  string
	RemoteSourceOauth2RefreshToken string
}
type LoginUserResponse struct {
	Token string
	User  *types.User
}

func (c *CommandHandler) LoginUser(ctx context.Context, req *LoginUserRequest) (*LoginUserResponse, error) {
	rs, _, err := c.configstoreClient.GetRemoteSourceByName(ctx, req.RemoteSourceName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get remote source %q", req.RemoteSourceName)
	}
	c.log.Infof("rs: %s", util.Dump(rs))

	accessToken, err := common.GetAccessToken(rs.AuthType, req.RemoteSourceUserAccessToken, req.RemoteSourceOauth2AccessToken)
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

	user, _, err := c.configstoreClient.GetUserByLinkedAccountRemoteUserAndSource(ctx, remoteUserInfo.ID, rs.ID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get user for remote user id %q and remote source %q", remoteUserInfo.ID, rs.ID)
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
		return nil, errors.Errorf("linked account for user %q for remote source %q doesn't exist", user.UserName, rs.Name)
	}

	// Update oauth tokens if they have changed since the getuserinfo request may have updated them
	if la.Oauth2AccessToken != req.RemoteSourceOauth2AccessToken ||
		la.Oauth2RefreshToken != req.RemoteSourceOauth2RefreshToken ||
		la.UserAccessToken != req.RemoteSourceUserAccessToken {

		la.Oauth2AccessToken = req.RemoteSourceOauth2AccessToken
		la.Oauth2RefreshToken = req.RemoteSourceOauth2RefreshToken
		la.UserAccessToken = req.RemoteSourceUserAccessToken

		creq := &csapi.UpdateUserLARequest{
			RemoteUserID:       la.RemoteUserID,
			RemoteUserName:     la.RemoteUserName,
			Oauth2AccessToken:  la.Oauth2AccessToken,
			Oauth2RefreshToken: la.Oauth2RefreshToken,
			UserAccessToken:    la.UserAccessToken,
		}

		c.log.Infof("updating user %q linked account", user.UserName)
		la, _, err = c.configstoreClient.UpdateUserLA(ctx, user.UserName, la.ID, creq)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to update user")
		}
		c.log.Infof("linked account %q for user %q updated", la.ID, user.UserName)
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

type RemoteSourceAuthResponse struct {
	Oauth2Redirect string
	Response       interface{}
}

func (c *CommandHandler) HandleRemoteSourceAuth(ctx context.Context, rs *types.RemoteSource, loginName, loginPassword, requestType string, req interface{}) (*RemoteSourceAuthResponse, error) {
	switch rs.AuthType {
	case types.RemoteSourceAuthTypeOauth2:
		oauth2Source, err := common.GetOauth2Source(rs, "")
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create git source")
		}
		token, err := common.GenerateJWTToken(c.sd, rs.Name, requestType, req)
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
		accessToken, err := passwordSource.LoginPassword(loginName, loginPassword)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to login to remote source %q with login name %q", rs.Name, loginName)
		}
		c.log.Infof("access token: %s", accessToken)
		requestj, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		cres, err := c.HandleRemoteSourceAuthRequest(ctx, requestType, string(requestj), accessToken, "", "")
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

type RemoteSourceAuthResult struct {
	RequestType string
	Response    interface{}
}

type CreateUserLAResponse struct {
	LinkedAccount *types.LinkedAccount
}

func (c *CommandHandler) HandleRemoteSourceAuthRequest(ctx context.Context, requestType, requestString string, userAccessToken, Oauth2AccessToken, Oauth2RefreshToken string) (*RemoteSourceAuthResult, error) {
	switch requestType {
	case "createuserla":
		var req *CreateUserLARequest
		if err := json.Unmarshal([]byte(requestString), &req); err != nil {
			return nil, errors.Errorf("failed to unmarshal request")
		}

		creq := &CreateUserLARequest{
			UserName:                       req.UserName,
			RemoteSourceName:               req.RemoteSourceName,
			RemoteSourceUserAccessToken:    userAccessToken,
			RemoteSourceOauth2AccessToken:  Oauth2AccessToken,
			RemoteSourceOauth2RefreshToken: Oauth2RefreshToken,
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

	case "loginuser":
		var req *LoginUserRequest
		if err := json.Unmarshal([]byte(requestString), &req); err != nil {
			return nil, errors.Errorf("failed to unmarshal request")
		}

		creq := &LoginUserRequest{
			RemoteSourceName:               req.RemoteSourceName,
			RemoteSourceUserAccessToken:    userAccessToken,
			RemoteSourceOauth2AccessToken:  Oauth2AccessToken,
			RemoteSourceOauth2RefreshToken: Oauth2RefreshToken,
		}
		cresp, err := c.LoginUser(ctx, creq)
		if err != nil {
			return nil, err
		}
		return &RemoteSourceAuthResult{
			RequestType: requestType,
			Response: &LoginUserResponse{
				Token: cresp.Token,
				User:  cresp.User,
			},
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
	requestType := claims["request_type"].(string)
	requestString := claims["request"].(string)

	rs, _, err := c.configstoreClient.GetRemoteSourceByName(ctx, remoteSourceName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get remote source %q", remoteSourceName)
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

	return c.HandleRemoteSourceAuthRequest(ctx, requestType, requestString, "", oauth2Token.AccessToken, oauth2Token.RefreshToken)
}
