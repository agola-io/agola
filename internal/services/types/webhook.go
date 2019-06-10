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

package types

type WebhookEvent string

const (
	WebhookEventPush        WebhookEvent = "push"
	WebhookEventTag         WebhookEvent = "tag"
	WebhookEventPullRequest WebhookEvent = "pull_request"
)

type WebhookData struct {
	Event     WebhookEvent `json:"event,omitempty"`
	ProjectID string       `json:"project_id,omitempty"`
	SSHURL    string       `json:"ssh_url"`

	CompareLink string `json:"compare_link,omitempty"` // Compare link to remote git source
	CommitLink  string `json:"commit_link,omitempty"`  // Commit link to remote git source
	CommitSHA   string `json:"commit_sha,omitempty"`   // commit SHA (SHA1 but also future SHA like SHA256)
	Ref         string `json:"ref,omitempty"`          // Ref containing the commit SHA
	Message     string `json:"message,omitempty"`      // Message to use (Push last commit message summary, PR title, Tag message etc...)
	Sender      string `json:"sender,omitempty"`
	Avatar      string `json:"avatar,omitempty"`

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
	WebURL string `json:"web_url,omitempty"`
	Path   string `json:"path,omitempty"`
}
