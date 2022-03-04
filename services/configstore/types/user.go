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

	stypes "agola.io/agola/services/types"

	"github.com/gofrs/uuid"
)

const (
	UserKind    = "user"
	UserVersion = "v0.1.0"
)

type User struct {
	stypes.TypeMeta
	stypes.ObjectMeta

	Name string `json:"name,omitempty"`

	// Secret is a secret that could be used for signing or other purposes. It
	// should never be directly exposed to external services
	Secret string `json:"secret,omitempty"`

	// Admin defines if the user is a global admin
	Admin bool `json:"admin,omitempty"`
}

func NewUser() *User {
	return &User{
		TypeMeta: stypes.TypeMeta{
			Kind:    UserKind,
			Version: UserVersion,
		},
		ObjectMeta: stypes.ObjectMeta{
			ID: uuid.Must(uuid.NewV4()).String(),
		},
	}
}

const (
	UserTokenKind    = "usertoken"
	UserTokenVersion = "v0.1.0"
)

type UserToken struct {
	stypes.TypeMeta
	stypes.ObjectMeta

	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`

	UserID string `json:"user_id,omitempty"`
}

func NewUserToken() *UserToken {
	return &UserToken{
		TypeMeta: stypes.TypeMeta{
			Kind:    UserTokenKind,
			Version: UserTokenVersion,
		},
		ObjectMeta: stypes.ObjectMeta{
			ID: uuid.Must(uuid.NewV4()).String(),
		},
	}
}

const (
	LinkedAccountKind    = "linkedaccount"
	LinkedAccountVersion = "v0.1.0"
)

type LinkedAccount struct {
	stypes.TypeMeta
	stypes.ObjectMeta

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

func NewLinkedAccount() *LinkedAccount {
	return &LinkedAccount{
		TypeMeta: stypes.TypeMeta{
			Kind:    LinkedAccountKind,
			Version: LinkedAccountVersion,
		},
		ObjectMeta: stypes.ObjectMeta{
			ID: uuid.Must(uuid.NewV4()).String(),
		},
	}
}
