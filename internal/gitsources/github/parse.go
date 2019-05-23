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

package github

import (
	"fmt"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/google/go-github/v25/github"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	errors "golang.org/x/xerrors"
)

const (
	hookEvent       = "X-Gitea-Event"
	signatureHeader = "X-Gitea-Signature"

	hookPush        = "push"
	hookPullRequest = "pull_request"

	prStateOpen = "open"

	prActionOpen = "opened"
	prActionSync = "synchronize"
)

func (c *Client) ParseWebhook(r *http.Request, secret string) (*types.WebhookData, error) {
	payload, err := github.ValidatePayload(r, []byte(secret))
	if err != nil {
		return nil, errors.Errorf("wrong webhook signature: %w", err)
	}
	event, err := github.ParseWebHook(github.WebHookType(r), payload)
	if err != nil {
		return nil, errors.Errorf("failed to parse webhook: %w", err)
	}
	switch event := event.(type) {
	case *github.PushEvent:
		return webhookDataFromPush(event)
	case *github.PullRequestEvent:
		return webhookDataFromPullRequest(event)
	default:
		return nil, errors.Errorf("unknown webhook event type: %q", r.Header.Get(hookEvent))
	}
}

func webhookDataFromPush(hook *github.PushEvent) (*types.WebhookData, error) {
	log.Printf("hook: %s", util.Dump(hook))
	sender := hook.Sender.Name
	if sender == nil {
		sender = hook.Sender.Login
	}

	// common data
	whd := &types.WebhookData{
		CommitSHA:   *hook.After,
		SSHURL:      *hook.Repo.SSHURL,
		Ref:         *hook.Ref,
		CompareLink: *hook.Compare,
		CommitLink:  fmt.Sprintf("%s/commit/%s", *hook.Repo.URL, *hook.After),
		Sender:      *sender,

		Repo: types.WebhookDataRepo{
			Path:   path.Join(*hook.Repo.Owner.Name, *hook.Repo.Name),
			WebURL: *hook.Repo.URL,
		},
	}

	switch {
	case strings.HasPrefix(*hook.Ref, "refs/heads/"):
		whd.Event = types.WebhookEventPush
		whd.Branch = strings.TrimPrefix(*hook.Ref, "refs/heads/")
		whd.BranchLink = fmt.Sprintf("%s/src/branch/%s", *hook.Repo.URL, whd.Branch)
		if len(hook.Commits) > 0 {
			whd.Message = *hook.Commits[0].Message
		}
	case strings.HasPrefix(*hook.Ref, "refs/tags/"):
		whd.Event = types.WebhookEventTag
		whd.Tag = strings.TrimPrefix(*hook.Ref, "refs/tags/")
		whd.TagLink = fmt.Sprintf("%s/src/tag/%s", *hook.Repo.URL, whd.Tag)
		whd.Message = fmt.Sprintf("Tag %s", whd.Tag)
	default:
		// ignore received webhook since it doesn't have a ref we're interested in
		return nil, fmt.Errorf("unsupported webhook ref %q", *hook.Ref)
	}

	return whd, nil
}

// helper function that extracts the Build data from a Gitea pull_request hook
func webhookDataFromPullRequest(hook *github.PullRequestEvent) (*types.WebhookData, error) {
	log.Printf("hook: %s", util.Dump(hook))

	// skip non open pull requests
	if *hook.PullRequest.State != prStateOpen {
		return nil, nil
	}
	// only accept actions that have new commits
	if *hook.Action != prActionOpen && *hook.Action != prActionSync {
		return nil, nil
	}

	sender := *hook.Sender.Name
	if sender == "" {
		sender = *hook.Sender.Login
	}
	whd := &types.WebhookData{
		Event:           types.WebhookEventPullRequest,
		CommitSHA:       *hook.PullRequest.Head.SHA,
		SSHURL:          *hook.Repo.SSHURL,
		Ref:             fmt.Sprintf("refs/pull/%d/head", *hook.Number),
		CommitLink:      fmt.Sprintf("%s/commit/%s", *hook.Repo.URL, *hook.PullRequest.Head.SHA),
		Branch:          *hook.PullRequest.Base.Ref,
		Message:         *hook.PullRequest.Title,
		Sender:          sender,
		PullRequestID:   strconv.FormatInt(*hook.PullRequest.ID, 10),
		PullRequestLink: *hook.PullRequest.URL,

		Repo: types.WebhookDataRepo{
			Path:   path.Join(*hook.Repo.Owner.Login, *hook.Repo.Name),
			WebURL: *hook.Repo.URL,
		},
	}

	return whd, nil
}
