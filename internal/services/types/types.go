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
)

type WebhookEvent string

const (
	WebhookEventPush        WebhookEvent = "push"
	WebhookEventTag         WebhookEvent = "tag"
	WebhookEventPullRequest WebhookEvent = "pull_request"
)

type RunType string

const (
	RunTypeProject RunType = "project"
	RunTypeUser    RunType = "user"
)

type WebhookData struct {
	Event     WebhookEvent `json:"event,omitempty"`
	ProjectID string       `json:"project_id,omitempty"`

	CompareLink  string `json:"compare_link,omitempty"`   // Pimray link to source. It can be the commit
	CommitLink   string `json:"commit_link,omitempty"`    // Pimray link to source. It can be the commit
	CommitSHA    string `json:"commit_sha,omitempty"`     // commit SHA (SHA1 but also future SHA like SHA256)
	OldCommitSHA string `json:"old_commit_sha,omitempty"` // commit SHA of the head before this push
	Ref          string `json:"ref,omitempty"`            // Ref containing the commit SHA
	Message      string `json:"message,omitempty"`        // Message to use (Push last commit message summary, PR title, Tag message etc...)
	Sender       string `json:"sender,omitempty"`
	Avatar       string `json:"avatar,omitempty"`

	Branch     string `json:"branch,omitempty"`
	BranchLink string `json:"branch_link,omitempty"`

	Tag     string `json:"tag,omitempty"`
	TagLink string `json:"tag_link,omitempty"`

	// use a string if on some platform (current or future) some PRs id will not be numbers
	PullRequestID   string `json:"pull_request_id,omitempty"`
	PullRequestLink string `json:"link,omitempty"` // Link to pull request

	Repo WebhookDataRepo `json:"repo,omitempty"`
}

type WebhookDataRepo struct {
	Name     string `json:"name,omitempty"`
	Owner    string `json:"owner,omitempty"`
	FullName string `json:"full_name,omitempty"`
	RepoURL  string `json:"repo_url,omitempty"`
}

// Configstore types

type User struct {
	ID string `json:"id,omitempty"`

	UserName string `json:"user_name,omitempty"`

	LinkedAccounts map[string]*LinkedAccount `json:"linked_accounts,omitempty"`

	// Optional local auth
	Password string `json:"password,omitempty"`

	Tokens map[string]string `json:"tokens,omitempty"`
}

type RemoteSourceType string

const (
	RemoteSourceTypeGitea  RemoteSourceType = "gitea"
	RemoteSourceTypeGithub RemoteSourceType = "github"
	RemoteSourceTypeGitlab RemoteSourceType = "gitlab"
)

type RemoteSourceAuthType string

const (
	RemoteSourceAuthTypePassword RemoteSourceAuthType = "password"
	RemoteSourceAuthTypeOauth2   RemoteSourceAuthType = "oauth2"
)

type RemoteSource struct {
	ID string `json:"id,omitempty"`

	Name   string `json:"name,omitempty"`
	APIURL string `json:"apiurl,omitempty"`

	SkipVerify bool `json:"skip_verify,omitempty"`

	Type     RemoteSourceType     `json:"type,omitempty"`
	AuthType RemoteSourceAuthType `json:"auth_type,omitempty"`

	// Oauth2 data
	Oauth2ClientID     string `json:"client_id,omitempty"`
	Oauth2ClientSecret string `json:"client_secret,omitempty"`
}

type LinkedAccount struct {
	ID string `json:"id,omitempty"`

	RemoteUserID   string `json:"remote_user_id,omitempty"`
	RemoteUserName string `json:"remote_username,omitempty"`

	RemoteSourceID string `json:"remote_source_id,omitempty"`

	UserAccessToken string `json:"user_access_token,omitempty"`

	Oauth2AccessToken  string        `json:"oauth2_access_token,omitempty"`
	Oauth2RefreshToken string        `json:"oauth2_refresh_token,omitempty"`
	Oauth2Expire       time.Duration `json:"oauth2_expire,omitempty"`
}

type Project struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`

	// Project repository path. It may be different for every kind of git source.
	// It's needed to get git source needed information like the repo owner and
	// repo user
	// Examples: sgotti/agola (for github, gitea etc... sources)
	Path string `json:"path,omitempty"`

	LinkedAccountID string `json:"linked_account_id,omitempty"`

	CloneURL      string `json:"clone_url,omitempty"`
	SSHPrivateKey string `json:"ssh_private_key,omitempty"` // PEM Encoded private key

	SkipSSHHostKeyCheck bool `json:"skip_ssh_host_key_check,omitempty"`
}
