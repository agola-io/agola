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

	"agola.io/agola/internal/services/types"
	"agola.io/agola/internal/util"
	errors "golang.org/x/xerrors"
)

type GroupType string

const (
	// base groups
	GroupTypeProject GroupType = "project"
	GroupTypeUser    GroupType = "user"

	// sub groups
	GroupTypeBranch      GroupType = "branch"
	GroupTypeTag         GroupType = "tag"
	GroupTypePullRequest GroupType = "pr"

	ApproversAnnotation = "approvers"
)

func WebHookEventToRunRefType(we types.WebhookEvent) types.RunRefType {
	switch we {
	case types.WebhookEventPush:
		return types.RunRefTypeBranch
	case types.WebhookEventTag:
		return types.RunRefTypeTag
	case types.WebhookEventPullRequest:
		return types.RunRefTypePullRequest
	}

	panic(fmt.Errorf("invalid webhook event type: %q", we))
}

func GenRunGroup(baseGroupType GroupType, baseGroupID string, groupType GroupType, group string) string {
	// we pathescape the branch name to handle branches with slashes and make the
	// branch a single path entry
	return path.Join("/", string(baseGroupType), baseGroupID, string(groupType), url.PathEscape(group))
}

func GroupTypeIDFromRunGroup(group string) (GroupType, string, error) {
	pl := util.PathList(group)
	if len(pl) < 2 {
		return "", "", errors.Errorf("cannot determine group project id, wrong group path %q", group)
	}
	return GroupType(pl[0]), pl[1], nil
}
