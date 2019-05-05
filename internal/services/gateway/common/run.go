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

package common

import (
	"fmt"
	"net/url"
	"path"

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
)

type GroupType string

const (
	GroupTypeProject     GroupType = "project"
	GroupTypeUser        GroupType = "user"
	GroupTypeBranch      GroupType = "branch"
	GroupTypeTag         GroupType = "tag"
	GroupTypePullRequest GroupType = "pr"
)

func GenRunGroup(baseGroupType GroupType, baseGroupID string, webhookData *types.WebhookData) string {
	// we pathescape the branch name to handle branches with slashes and make the
	// branch a single path entry
	switch webhookData.Event {
	case types.WebhookEventPush:
		return path.Join("/", string(baseGroupType), baseGroupID, string(GroupTypeBranch), url.PathEscape(webhookData.Branch))
	case types.WebhookEventTag:
		return path.Join("/", string(baseGroupType), baseGroupID, string(GroupTypeTag), url.PathEscape(webhookData.Tag))
	case types.WebhookEventPullRequest:
		return path.Join("/", string(baseGroupType), baseGroupID, string(GroupTypePullRequest), url.PathEscape(webhookData.PullRequestID))
	}

	panic(fmt.Errorf("invalid webhook event type: %q", webhookData.Event))
}

func ProjectIDFromRunGroup(group string) (string, error) {
	pl := util.PathList(group)
	if len(pl) < 2 {
		return "", errors.Errorf("cannot determine group project id, wrong group path %q", group)
	}
	return pl[1], nil
}
