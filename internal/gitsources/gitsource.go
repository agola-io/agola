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

package gitsource

import (
	"net/http"

	"github.com/sorintlab/agola/internal/services/types"
	"golang.org/x/oauth2"
)

type CommitStatus string

const (
	CommitStatusPending CommitStatus = "pending"
	CommitStatusSuccess CommitStatus = "success"
	CommitStatusFailed  CommitStatus = "failed"
)

type GitSource interface {
	GetRepoInfo(repopath string) (*RepoInfo, error)
	GetFile(repopath, commit, file string) ([]byte, error)
	DeleteDeployKey(repopath, title string) error
	CreateDeployKey(repopath, title, pubKey string, readonly bool) error
	UpdateDeployKey(repopath, title, pubKey string, readonly bool) error
	DeleteRepoWebhook(repopath, url string) error
	CreateRepoWebhook(repopath, url, secret string) error
	ParseWebhook(r *http.Request) (*types.WebhookData, error)
	CreateCommitStatus(repopath, commitSHA string, status CommitStatus, targetURL, description, context string) error
	ListUserRepos() ([]*RepoInfo, error)
}

type UserSource interface {
	GetUserInfo() (*UserInfo, error)
}

type PasswordSource interface {
	UserSource
	LoginPassword(username, password, tokenName string) (string, error)
}

type Oauth2Source interface {
	UserSource
	// GetOauth2AuthorizationURL return the authorization request URL to the
	// authorization server
	GetOauth2AuthorizationURL(callbackURL, state string) (redirectURL string, err error)
	// RequestOauth2Token requests the oauth2 token to the authorization server
	RequestOauth2Token(callbackURL, code string) (*oauth2.Token, error)
	// RefreshOauth2Token refreshed the oauth2 token
	RefreshOauth2Token(refreshToken string) (*oauth2.Token, error)
}

type RepoInfo struct {
	ID           string
	Path         string
	SSHCloneURL  string
	HTTPCloneURL string
}

type UserInfo struct {
	ID        string
	LoginName string
	Email     string
}
