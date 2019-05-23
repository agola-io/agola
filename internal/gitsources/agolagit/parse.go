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

package agolagit

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/sorintlab/agola/internal/services/types"

	errors "golang.org/x/xerrors"
)

const (
	hookEvent = "X-Gitea-Event"

	hookPush        = "push"
	hookPullRequest = "pull_request"

	prStateOpen = "open"

	prActionOpen = "opened"
	prActionSync = "synchronized"
)

func (c *Client) ParseWebhook(r *http.Request, secret string) (*types.WebhookData, error) {
	data, err := ioutil.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}

	switch r.Header.Get(hookEvent) {
	case hookPush:
		return parsePushHook(data)
	case hookPullRequest:
		return parsePullRequestHook(data)
	default:
		return nil, errors.Errorf("unknown webhook event type: %q", r.Header.Get(hookEvent))
	}
}

func parsePushHook(data []byte) (*types.WebhookData, error) {
	push := new(pushHook)
	err := json.Unmarshal(data, push)
	if err != nil {
		return nil, err
	}

	return webhookDataFromPush(push)
}

func parsePullRequestHook(data []byte) (*types.WebhookData, error) {
	prhook := new(pullRequestHook)
	err := json.Unmarshal(data, prhook)
	if err != nil {
		return nil, err
	}

	// skip non open pull requests
	if prhook.PullRequest.State != prStateOpen {
		return nil, nil
	}
	// only accept actions that have new commits
	if prhook.Action != prActionOpen && prhook.Action != prActionSync {
		return nil, nil
	}

	return webhookDataFromPullRequest(prhook), nil
}

func webhookDataFromPush(hook *pushHook) (*types.WebhookData, error) {
	sender := hook.Sender.Username
	if sender == "" {
		sender = hook.Sender.Login
	}

	// common data
	whd := &types.WebhookData{
		CommitSHA:   hook.After,
		Ref:         hook.Ref,
		CompareLink: hook.Compare,
		CommitLink:  fmt.Sprintf("%s/commit/%s", hook.Repo.URL, hook.After),
		Sender:      sender,

		Repo: types.WebhookDataRepo{
			Path:   path.Join(hook.Repo.Owner.Username, hook.Repo.Name),
			WebURL: hook.Repo.URL,
		},
	}

	whd.Event = types.WebhookEventPush
	whd.Branch = strings.TrimPrefix(hook.Ref, "refs/heads/")
	whd.BranchLink = fmt.Sprintf("%s/src/branch/%s", hook.Repo.URL, whd.Branch)
	if len(hook.Commits) > 0 {
		whd.Message = hook.Commits[0].Message
	}

	return whd, nil
}

// helper function that extracts the Build data from a Gitea pull_request hook
func webhookDataFromPullRequest(hook *pullRequestHook) *types.WebhookData {
	sender := hook.Sender.Username
	if sender == "" {
		sender = hook.Sender.Login
	}
	build := &types.WebhookData{
		Event:           types.WebhookEventPullRequest,
		CommitSHA:       hook.PullRequest.Head.Sha,
		Ref:             fmt.Sprintf("refs/pull/%d/head", hook.Number),
		CommitLink:      fmt.Sprintf("%s/commit/%s", hook.Repo.URL, hook.PullRequest.Head.Sha),
		Branch:          hook.PullRequest.Base.Ref,
		Message:         hook.PullRequest.Title,
		Sender:          sender,
		PullRequestID:   strconv.FormatInt(hook.PullRequest.ID, 10),
		PullRequestLink: hook.PullRequest.URL,

		Repo: types.WebhookDataRepo{
			Path:   path.Join(hook.Repo.Owner.Username, hook.Repo.Name),
			WebURL: hook.Repo.URL,
		},
	}
	return build
}
