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

package gitsource

import (
	"errors"
	"net/http"

	"github.com/sorintlab/agola/internal/services/types"
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
