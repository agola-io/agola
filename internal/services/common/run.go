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

package common

import (
	"fmt"
	"net/url"
	"path"

	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
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
