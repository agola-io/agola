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

package gitlab

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	errors "golang.org/x/xerrors"
)

const (
	hookEvent   = "X-Gitlab-Event"
	tokenHeader = "X-Gitlab-Token"

	hookPush        = "Push Hook"
	hookTagPush     = "Tag Push Hook"
	hookPullRequest = "Merge Request Hook"

	prStateOpen = "open"

	prActionOpen = "opened"
	prActionSync = "synchronized"
)

func (c *Client) ParseWebhook(r *http.Request, secret string) (*types.WebhookData, error) {
	data, err := ioutil.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}

	log.Printf("r: %s", util.Dump(r))
	log.Printf("data: %s", data)

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
	log.Printf("hook: %s", util.Dump(hook))
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
		//CompareLink: hook.Compare,
		//CommitLink: fmt.Sprintf("%s/commit/%s", hook.Repo.URL, hook.After),
		Sender: sender,

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
	log.Printf("hook: %s", util.Dump(hook))
	// TODO(sgotti) Use PR opener username or last commit user name?
	sender := hook.User.Name
	if sender == "" {
		sender = hook.User.Username
	}
	//sender := hook.ObjectAttributes.LastCommit.Author.Name
	//if sender == "" {
	//	sender := hook.ObjectAttributes.LastCommit.Author.UserName
	//}
	build := &types.WebhookData{
		Event:     types.WebhookEventPullRequest,
		CommitSHA: hook.ObjectAttributes.LastCommit.ID,
		SSHURL:    hook.Project.SSHURL,
		Ref:       fmt.Sprintf("refs/merge-requests/%d/head", hook.ObjectAttributes.Iid),
		//CommitLink:      fmt.Sprintf("%s/commit/%s", hook.Repo.URL, hook.PullRequest.Head.Sha),
		CommitLink:      hook.ObjectAttributes.LastCommit.URL,
		Branch:          hook.ObjectAttributes.SourceBranch,
		Message:         hook.ObjectAttributes.Title,
		Sender:          sender,
		PullRequestID:   strconv.Itoa(hook.ObjectAttributes.Iid),
		PullRequestLink: hook.ObjectAttributes.URL,

		Repo: types.WebhookDataRepo{
			Path:   hook.Project.PathWithNamespace,
			WebURL: hook.Project.WebURL,
		},
	}
	return build
}
