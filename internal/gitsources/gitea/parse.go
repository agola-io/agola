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

package gitea

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path"
	"strconv"
	"strings"

	"agola.io/agola/internal/services/types"

	errors "golang.org/x/xerrors"
)

const (
	hookEvent       = "X-Gitea-Event"
	signatureHeader = "X-Gitea-Signature"

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

	// verify signature
	signature := r.Header.Get(signatureHeader)
	// old versions of gitea doesn't provide a signature
	if secret != "" && signature != "" {
		ds, err := hex.DecodeString(signature)
		if err != nil {
			return nil, errors.Errorf("wrong webhook signature")
		}
		h := hmac.New(sha256.New, []byte(secret))
		if _, err := h.Write(data); err != nil {
			return nil, errors.Errorf("failed to calculate webhook signature")
		}
		cs := h.Sum(nil)
		if !hmac.Equal(cs, ds) {
			return nil, errors.Errorf("wrong webhook signature")
		}
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
		SSHURL:      hook.Repo.SSHURL,
		Ref:         hook.Ref,
		CompareLink: hook.Compare,
		CommitLink:  fmt.Sprintf("%s/commit/%s", hook.Repo.URL, hook.After),
		Sender:      sender,

		Repo: types.WebhookDataRepo{
			Path:   path.Join(hook.Repo.Owner.Username, hook.Repo.Name),
			WebURL: hook.Repo.URL,
		},
	}

	switch {
	case strings.HasPrefix(hook.Ref, "refs/heads/"):
		whd.Event = types.WebhookEventPush
		whd.Branch = strings.TrimPrefix(hook.Ref, "refs/heads/")
		whd.BranchLink = fmt.Sprintf("%s/src/branch/%s", hook.Repo.URL, whd.Branch)
		if len(hook.Commits) > 0 {
			whd.Message = hook.Commits[0].Message
		}
	case strings.HasPrefix(hook.Ref, "refs/tags/"):
		whd.Event = types.WebhookEventTag
		whd.Tag = strings.TrimPrefix(hook.Ref, "refs/tags/")
		whd.TagLink = fmt.Sprintf("%s/src/tag/%s", hook.Repo.URL, whd.Tag)
		whd.Message = fmt.Sprintf("Tag %s", whd.Tag)
	default:
		// ignore received webhook since it doesn't have a ref we're interested in
		return nil, fmt.Errorf("unsupported webhook ref %q", hook.Ref)
	}

	return whd, nil
}

// helper function that extracts the Build data from a Gitea pull_request hook
func webhookDataFromPullRequest(hook *pullRequestHook) *types.WebhookData {
	sender := hook.Sender.Username
	if sender == "" {
		sender = hook.Sender.Login
	}
	prFromSameRepo := false
	if hook.PullRequest.Base.Repo.URL == hook.PullRequest.Head.Repo.URL {
		prFromSameRepo = true
	}
	whd := &types.WebhookData{
		Event:           types.WebhookEventPullRequest,
		CommitSHA:       hook.PullRequest.Head.Sha,
		SSHURL:          hook.Repo.SSHURL,
		Ref:             fmt.Sprintf("refs/pull/%d/head", hook.Number),
		CommitLink:      fmt.Sprintf("%s/commit/%s", hook.Repo.URL, hook.PullRequest.Head.Sha),
		Message:         hook.PullRequest.Title,
		Sender:          sender,
		PullRequestID:   strconv.FormatInt(hook.PullRequest.ID, 10),
		PullRequestLink: hook.PullRequest.URL,
		PRFromSameRepo:  prFromSameRepo,

		Repo: types.WebhookDataRepo{
			Path:   path.Join(hook.Repo.Owner.Username, hook.Repo.Name),
			WebURL: hook.Repo.URL,
		},
	}

	return whd
}
