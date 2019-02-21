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
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
)

const (
	hookEvent = "X-Gitea-Event"

	hookPush        = "push"
	hookPullRequest = "pull_request"

	prStateOpen = "open"

	prActionOpen = "opened"
	prActionSync = "synchronized"
)

func parseWebhook(r *http.Request) (*types.WebhookData, error) {
	switch r.Header.Get(hookEvent) {
	case hookPush:
		return parsePushHook(r.Body)
	case hookPullRequest:
		return parsePullRequestHook(r.Body)
	default:
		return nil, errors.Errorf("unknown webhook event type: %q", r.Header.Get(hookEvent))
	}
}

func parsePush(r io.Reader) (*pushHook, error) {
	push := new(pushHook)
	err := json.NewDecoder(r).Decode(push)
	return push, err
}

func parsePullRequest(r io.Reader) (*pullRequestHook, error) {
	pr := new(pullRequestHook)
	err := json.NewDecoder(r).Decode(pr)
	return pr, err
}

func parsePushHook(payload io.Reader) (*types.WebhookData, error) {
	push, err := parsePush(payload)
	if err != nil {
		return nil, err
	}

	return webhookDataFromPush(push)
}

func parsePullRequestHook(payload io.Reader) (*types.WebhookData, error) {
	prhook, err := parsePullRequest(payload)
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
	log.Printf("hook: %s", util.Dump(hook))
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
			Name:     hook.Repo.Name,
			Owner:    hook.Repo.Owner.Username,
			FullName: hook.Repo.FullName,
			RepoURL:  hook.Repo.URL,
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
	log.Printf("hook: %s", util.Dump(hook))
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
			Name:     hook.Repo.Name,
			Owner:    hook.Repo.Owner.Username,
			FullName: hook.Repo.FullName,
			RepoURL:  hook.Repo.URL,
		},
	}
	return build
}
