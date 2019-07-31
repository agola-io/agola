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

package types

import (
	"time"

	cstypes "agola.io/agola/services/configstore/types"
)

type CreateUserRequest struct {
	UserName string `json:"user_name"`

	CreateUserLARequest *CreateUserLARequest `json:"create_user_la_request"`
}

type UpdateUserRequest struct {
	UserName string `json:"user_name"`
}

type CreateUserLARequest struct {
	RemoteSourceName           string    `json:"remote_source_name"`
	RemoteUserID               string    `json:"remote_user_id"`
	RemoteUserName             string    `json:"remote_user_name"`
	UserAccessToken            string    `json:"user_access_token"`
	Oauth2AccessToken          string    `json:"oauth2_access_token"`
	Oauth2RefreshToken         string    `json:"oauth2_refresh_token"`
	Oauth2AccessTokenExpiresAt time.Time `json:"oauth_2_access_token_expires_at"`
}

type UpdateUserLARequest struct {
	RemoteUserID               string    `json:"remote_user_id"`
	RemoteUserName             string    `json:"remote_user_name"`
	UserAccessToken            string    `json:"user_access_token"`
	Oauth2AccessToken          string    `json:"oauth2_access_token"`
	Oauth2RefreshToken         string    `json:"oauth2_refresh_token"`
	Oauth2AccessTokenExpiresAt time.Time `json:"oauth_2_access_token_expires_at"`
}

type CreateUserTokenRequest struct {
	TokenName string `json:"token_name"`
}

type CreateUserTokenResponse struct {
	Token string `json:"token"`
}

type UserOrgsResponse struct {
	Organization *cstypes.Organization
	Role         cstypes.MemberRole
}
