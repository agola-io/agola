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
	"errors"
	"net/http"

	"agola.io/agola/internal/services/types"
	"golang.org/x/oauth2"
)

type CommitStatus string

const (
	CommitStatusPending CommitStatus = "pending"
	CommitStatusSuccess CommitStatus = "success"
	CommitStatusError   CommitStatus = "error"
	CommitStatusFailed  CommitStatus = "failed"
)

var ErrUnauthorized = errors.New("unauthorized")

type GitSource interface {
	GetRepoInfo(repopath string) (*RepoInfo, error)
	GetFile(repopath, commit, file string) ([]byte, error)
	DeleteDeployKey(repopath, title string) error
	CreateDeployKey(repopath, title, pubKey string, readonly bool) error
	UpdateDeployKey(repopath, title, pubKey string, readonly bool) error
	DeleteRepoWebhook(repopath, url string) error
	CreateRepoWebhook(repopath, url, secret string) error
	ParseWebhook(r *http.Request, secret string) (*types.WebhookData, error)
	CreateCommitStatus(repopath, commitSHA string, status CommitStatus, targetURL, description, context string) error
	// ListUserRepos report repos where the user has the permission to create deploy keys and webhooks
	ListUserRepos() ([]*RepoInfo, error)
	GetRef(repopath, ref string) (*Ref, error)
	// RefType returns the ref type and the related name (branch, tag, pr id)
	RefType(ref string) (RefType, string, error)
	GetCommit(repopath, commitSHA string) (*Commit, error)

	BranchRef(branch string) string
	TagRef(tag string) string
	PullRequestRef(prID string) string

	CommitLink(repoInfo *RepoInfo, commitSHA string) string
	BranchLink(repoInfo *RepoInfo, branch string) string
	TagLink(repoInfo *RepoInfo, tag string) string
	PullRequestLink(repoInfo *RepoInfo, prID string) string
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
	HTMLURL      string
	SSHCloneURL  string
	HTTPCloneURL string
}

type UserInfo struct {
	ID        string
	LoginName string
	Email     string
}

type RefType int

const (
	RefTypeBranch RefType = iota
	RefTypeTag
	RefTypePullRequest
)

type Ref struct {
	Ref       string
	CommitSHA string
}

type Commit struct {
	SHA     string
	Message string
}
