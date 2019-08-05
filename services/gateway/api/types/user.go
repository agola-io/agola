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

type LinkedAccount struct {
	ID string `json:"id,omitempty"`

	RemoteUserID        string `json:"remote_user_id,omitempty"`
	RemoteUserName      string `json:"remote_username,omitempty"`
	RemoteUserAvatarURL string `json:"remote_user_avatar_url,omitempty"`

	RemoteSourceID string `json:"remote_source_id,omitempty"`
}

type CreateUserRequest struct {
	UserName string `json:"username"`
}

type UserResponse struct {
	ID             string                   `json:"id"`
	UserName       string                   `json:"username"`
	Tokens         []string                 `json:"tokens"`
	LinkedAccounts []*LinkedAccountResponse `json:"linked_accounts"`
}

type LinkedAccountResponse struct {
	ID                  string `json:"id"`
	RemoteSourceID      string `json:"remote_source_id"`
	RemoteUserName      string `json:"remote_user_name"`
	RemoteUserAvatarURL string `json:"remote_user_avatar_url"`
}

type CreateUserLARequest struct {
	RemoteSourceName          string `json:"remote_source_name"`
	RemoteSourceLoginName     string `json:"remote_source_login_name"`
	RemoteSourceLoginPassword string `json:"remote_source_login_password"`
}

type CreateUserLAResponse struct {
	LinkedAccount  *LinkedAccount `json:"linked_account"`
	Oauth2Redirect string         `json:"oauth2_redirect"`
}

type CreateUserTokenRequest struct {
	TokenName string `json:"token_name"`
}

type CreateUserTokenResponse struct {
	Token string `json:"token"`
}

type RegisterUserRequest struct {
	CreateUserRequest
	CreateUserLARequest
}

type RegisterUserResponse struct {
	Oauth2Redirect string `json:"oauth2_redirect"`
}

type UserInfo struct {
	ID        string
	LoginName string
	Email     string
}

type AuthorizeResponse struct {
	Oauth2Redirect   string    `json:"oauth2_redirect"`
	RemoteUserInfo   *UserInfo `json:"remote_user_info"`
	RemoteSourceName string    `json:"remote_source_name"`
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

type UserCreateRunRequest struct {
	RepoUUID  string `json:"repo_uuid,omitempty"`
	RepoPath  string `json:"repo_path,omitempty"`
	Branch    string `json:"branch,omitempty"`
	Tag       string `json:"tag,omitempty"`
	Ref       string `json:"ref,omitempty"`
	CommitSHA string `json:"commit_sha,omitempty"`
	Message   string `json:"message,omitempty"`

	PullRequestRefRegexes []string          `json:"pull_request_ref_regexes,omitempty"`
	Variables             map[string]string `json:"variables,omitempty"`
}
