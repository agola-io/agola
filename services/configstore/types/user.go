// Copyright 2022 Sorint.lab
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

	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
)

type User struct {
	sqlg.ObjectMeta

	Name string `json:"name,omitempty"`

	// Secret is a secret that could be used for signing or other purposes. It
	// should never be directly exposed to external services
	Secret string `json:"secret,omitempty"`

	// Admin defines if the user is a global admin
	Admin bool `json:"admin,omitempty"`
}

func NewUser(tx *sql.Tx) *User {
	return &User{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}

type UserToken struct {
	sqlg.ObjectMeta

	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`

	UserID string `json:"user_id,omitempty"`
}

func NewUserToken(tx *sql.Tx) *UserToken {
	return &UserToken{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}

type LinkedAccount struct {
	sqlg.ObjectMeta

	UserID string `json:"user_id,omitempty"`

	RemoteUserID        string `json:"remote_user_id,omitempty"`
	RemoteUserName      string `json:"remote_username,omitempty"`
	RemoteUserAvatarURL string `json:"remote_user_avatar_url,omitempty"`

	RemoteSourceID string `json:"remote_source_id,omitempty"`

	UserAccessToken string `json:"user_access_token,omitempty"`

	Oauth2AccessToken          string    `json:"oauth2_access_token,omitempty"`
	Oauth2RefreshToken         string    `json:"oauth2_refresh_token,omitempty"`
	Oauth2AccessTokenExpiresAt time.Time `json:"oauth_2_access_token_expires_at,omitempty"`
}

func NewLinkedAccount(tx *sql.Tx) *LinkedAccount {
	return &LinkedAccount{
		ObjectMeta: sqlg.NewObjectMeta(tx),
	}
}
