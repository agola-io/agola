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

package github

import (
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"

	"agola.io/agola/internal/services/types"

	"github.com/google/go-github/v29/github"
	errors "golang.org/x/xerrors"
)

const (
	prStateOpen = "open"

	prActionOpen = "opened"
	prActionSync = "synchronize"
)

func (c *Client) ParseWebhook(r *http.Request, secret string) (*types.WebhookData, error) {
	payload, err := github.ValidatePayload(r, []byte(secret))
	if err != nil {
		return nil, errors.Errorf("wrong webhook signature: %w", err)
	}
	webHookType := github.WebHookType(r)
	event, err := github.ParseWebHook(webHookType, payload)
	if err != nil {
		return nil, errors.Errorf("failed to parse webhook: %w", err)
	}
	switch event := event.(type) {
	case *github.PushEvent:
		return webhookDataFromPush(event)
	case *github.PullRequestEvent:
		return webhookDataFromPullRequest(event)
	default:
		return nil, errors.Errorf("unknown webhook event type: %q", webHookType)
	}
}

func webhookDataFromPush(hook *github.PushEvent) (*types.WebhookData, error) {
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
		CommitLink:  fmt.Sprintf("%s/commit/%s", *hook.Repo.HTMLURL, *hook.After),
		Sender:      *sender,

		Repo: types.WebhookDataRepo{
			Path:   path.Join(*hook.Repo.Owner.Name, *hook.Repo.Name),
			WebURL: *hook.Repo.HTMLURL,
		},
	}

	switch {
	case strings.HasPrefix(*hook.Ref, "refs/heads/"):
		whd.Event = types.WebhookEventPush
		whd.Branch = strings.TrimPrefix(*hook.Ref, "refs/heads/")
		whd.BranchLink = fmt.Sprintf("%s/tree/%s", *hook.Repo.HTMLURL, whd.Branch)
		whd.Message = *hook.HeadCommit.Message

	case strings.HasPrefix(*hook.Ref, "refs/tags/"):
		whd.Event = types.WebhookEventTag
		whd.Tag = strings.TrimPrefix(*hook.Ref, "refs/tags/")
		whd.TagLink = fmt.Sprintf("%s/tree/%s", *hook.Repo.HTMLURL, whd.Tag)
		whd.Message = fmt.Sprintf("Tag %s", whd.Tag)

		// if it's a signed tag hook.After points to the signed tag sha and not the
		// commit sha. In this case use hook.HeadCommit.ID
		if hook.HeadCommit.ID != nil {
			whd.CommitSHA = *hook.HeadCommit.ID
		}

	default:
		// ignore received webhook since it doesn't have a ref we're interested in
		return nil, fmt.Errorf("unsupported webhook ref %q", *hook.Ref)
	}

	return whd, nil
}

func webhookDataFromPullRequest(hook *github.PullRequestEvent) (*types.WebhookData, error) {
	// skip non open pull requests
	if *hook.PullRequest.State != prStateOpen {
		return nil, nil
	}
	// only accept actions that have new commits
	if *hook.Action != prActionOpen && *hook.Action != prActionSync {
		return nil, nil
	}

	sender := hook.Sender.Name
	if sender == nil {
		sender = hook.Sender.Login
	}
	prFromSameRepo := false
	if hook.PullRequest.Base.Repo.URL == hook.PullRequest.Head.Repo.URL {
		prFromSameRepo = true
	}

	whd := &types.WebhookData{
		Event:           types.WebhookEventPullRequest,
		CommitSHA:       *hook.PullRequest.Head.SHA,
		SSHURL:          *hook.Repo.SSHURL,
		Ref:             fmt.Sprintf("refs/pull/%d/head", *hook.Number),
		CommitLink:      fmt.Sprintf("%s/commit/%s", *hook.Repo.HTMLURL, *hook.PullRequest.Head.SHA),
		Message:         *hook.PullRequest.Title,
		Sender:          *sender,
		PullRequestID:   strconv.Itoa(*hook.PullRequest.Number),
		PullRequestLink: *hook.PullRequest.HTMLURL,
		PRFromSameRepo:  prFromSameRepo,

		Repo: types.WebhookDataRepo{
			Path:   path.Join(*hook.Repo.Owner.Login, *hook.Repo.Name),
			WebURL: *hook.Repo.HTMLURL,
		},
	}

	return whd, nil
}
