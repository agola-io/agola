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

package gitlab

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"agola.io/agola/internal/services/types"

	errors "golang.org/x/xerrors"
)

const (
	hookEvent   = "X-Gitlab-Event"
	tokenHeader = "X-Gitlab-Token"

	hookPush        = "Push Hook"
	hookTagPush     = "Tag Push Hook"
	hookPullRequest = "Merge Request Hook"
)

func (c *Client) ParseWebhook(r *http.Request, secret string) (*types.WebhookData, error) {
	data, err := ioutil.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}

	// verify token (gitlab doesn't sign the payload but just returns the provided
	// secret)
	if secret != "" {
		token := r.Header.Get(tokenHeader)
		if token != secret {
			return nil, errors.Errorf("wrong webhook token")
		}
	}

	switch r.Header.Get(hookEvent) {
	case hookPush:
		return parsePushHook(data)
	case hookTagPush:
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

	// skip push events with 0 commits. i.e. a tag deletion.
	if len(push.Commits) == 0 {
		return nil, nil
	}

	return webhookDataFromPush(push)
}

func parsePullRequestHook(data []byte) (*types.WebhookData, error) {
	prhook := new(pullRequestHook)
	err := json.Unmarshal(data, prhook)
	if err != nil {
		return nil, err
	}

	// TODO(sgotti) skip non open pull requests
	// TODO(sgotti) only accept actions that have new commits

	return webhookDataFromPullRequest(prhook), nil
}

func webhookDataFromPush(hook *pushHook) (*types.WebhookData, error) {
	sender := hook.UserName
	if sender == "" {
		sender = hook.UserUsername
	}

	// common data
	whd := &types.WebhookData{
		CommitSHA:  hook.After,
		SSHURL:     hook.Project.SSHURL,
		Ref:        hook.Ref,
		CommitLink: hook.Commits[0].URL,
		Sender:     sender,

		Repo: types.WebhookDataRepo{
			Path:   hook.Project.PathWithNamespace,
			WebURL: hook.Project.WebURL,
		},
	}

	switch {
	case strings.HasPrefix(hook.Ref, "refs/heads/"):
		whd.Event = types.WebhookEventPush
		whd.Branch = strings.TrimPrefix(hook.Ref, "refs/heads/")
		whd.BranchLink = fmt.Sprintf("%s/tree/%s", hook.Project.WebURL, whd.Branch)
		if len(hook.Commits) > 0 {
			whd.Message = hook.Commits[0].Message
		}
	case strings.HasPrefix(hook.Ref, "refs/tags/"):
		whd.Event = types.WebhookEventTag
		whd.Tag = strings.TrimPrefix(hook.Ref, "refs/tags/")
		whd.TagLink = fmt.Sprintf("%s/tree/%s", hook.Project.WebURL, whd.Tag)
		whd.Message = fmt.Sprintf("Tag %s", whd.Tag)
	default:
		// ignore received webhook since it doesn't have a ref we're interested in
		return nil, fmt.Errorf("unsupported webhook ref %q", hook.Ref)
	}

	return whd, nil
}

// helper function that extracts the Build data from a Gitea pull_request hook
func webhookDataFromPullRequest(hook *pullRequestHook) *types.WebhookData {
	// TODO(sgotti) Use PR opener username or last commit user name?
	sender := hook.User.Name
	if sender == "" {
		sender = hook.User.Username
	}
	prFromSameRepo := false
	if hook.ObjectAttributes.Source.URL == hook.ObjectAttributes.Target.URL {
		prFromSameRepo = true
	}

	whd := &types.WebhookData{
		Event:           types.WebhookEventPullRequest,
		CommitSHA:       hook.ObjectAttributes.LastCommit.ID,
		SSHURL:          hook.Project.SSHURL,
		Ref:             fmt.Sprintf("refs/merge-requests/%d/head", hook.ObjectAttributes.Iid),
		CommitLink:      hook.ObjectAttributes.LastCommit.URL,
		Message:         hook.ObjectAttributes.Title,
		Sender:          sender,
		PullRequestID:   strconv.Itoa(hook.ObjectAttributes.Iid),
		PullRequestLink: hook.ObjectAttributes.URL,
		PRFromSameRepo:  prFromSameRepo,

		Repo: types.WebhookDataRepo{
			Path:   hook.Project.PathWithNamespace,
			WebURL: hook.Project.WebURL,
		},
	}
	return whd
}
