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

package action

import (
	"context"

	"github.com/sorintlab/errors"

	scommon "agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"
)

func (h *ActionHandler) IsAuthUserOrgOwner(ctx context.Context, orgID string) (bool, error) {
	isAdmin := common.IsUserAdmin(ctx)
	if isAdmin {
		return true, nil
	}

	userID := common.CurrentUserID(ctx)
	if userID == "" {
		return false, nil
	}

	userOrg, _, err := h.configstoreClient.GetUserOrg(ctx, userID, orgID)
	if err != nil {
		if util.RemoteErrorIs(err, util.ErrNotExist) {
			return false, nil
		}
		return false, APIErrorFromRemoteError(err, util.WithAPIErrorMsg("failed to get user org"))
	}

	if userOrg.Role == cstypes.MemberRoleOwner {
		return true, nil
	}

	return false, nil
}

func (h *ActionHandler) IsAuthUserProjectOwner(ctx context.Context, ownerType cstypes.ObjectKind, ownerID string) (bool, error) {
	isAdmin := common.IsUserAdmin(ctx)
	if isAdmin {
		return true, nil
	}

	userID := common.CurrentUserID(ctx)
	if userID == "" {
		return false, nil
	}

	if ownerType == cstypes.ObjectKindUser {
		if userID == ownerID {
			return true, nil
		}
	}

	if ownerType == cstypes.ObjectKindOrg {
		userOrg, _, err := h.configstoreClient.GetUserOrg(ctx, userID, ownerID)
		if err != nil {
			if util.RemoteErrorIs(err, util.ErrNotExist) {
				return false, nil
			}
			return false, APIErrorFromRemoteError(err, util.WithAPIErrorMsg("failed to get user org"))
		}

		if userOrg.Role == cstypes.MemberRoleOwner {
			return true, nil
		}
	}

	return false, nil
}

func (h *ActionHandler) IsAuthUserMember(ctx context.Context, ownerType cstypes.ObjectKind, ownerID string) (bool, error) {
	isAdmin := common.IsUserAdmin(ctx)
	if isAdmin {
		return true, nil
	}

	userID := common.CurrentUserID(ctx)
	if userID == "" {
		return false, nil
	}

	if ownerType == cstypes.ObjectKindUser {
		if userID == ownerID {
			return true, nil
		}
	}

	if ownerType == cstypes.ObjectKindOrg {
		userOrg, _, err := h.configstoreClient.GetUserOrg(ctx, userID, ownerID)
		if err != nil {
			return false, APIErrorFromRemoteError(err, util.WithAPIErrorMsg("failed to get user orgs"))
		}

		if userOrg == nil {
			return false, nil
		}

		return true, nil
	}

	return false, nil
}

func (h *ActionHandler) IsAuthUserVariableOwner(ctx context.Context, parentType cstypes.ObjectKind, parentRef string) (bool, error) {
	var ownerType cstypes.ObjectKind
	var ownerID string
	switch parentType {
	case cstypes.ObjectKindProjectGroup:
		pg, _, err := h.configstoreClient.GetProjectGroup(ctx, parentRef)
		if err != nil {
			return false, APIErrorFromRemoteError(err, util.WithAPIErrorMsg("failed to get project group %q", parentRef))
		}
		ownerType = pg.OwnerType
		ownerID = pg.OwnerID
	case cstypes.ObjectKindProject:
		p, _, err := h.configstoreClient.GetProject(ctx, parentRef)
		if err != nil {
			return false, APIErrorFromRemoteError(err, util.WithAPIErrorMsg("failed to get project  %q", parentRef))
		}
		ownerType = p.OwnerType
		ownerID = p.OwnerID
	}

	return h.IsAuthUserProjectOwner(ctx, ownerType, ownerID)
}

func (h *ActionHandler) CanAuthUserGetRun(ctx context.Context, groupType scommon.GroupType, ref string) (bool, string, error) {
	var visibility cstypes.Visibility
	var ownerType cstypes.ObjectKind
	var refID string
	var ownerID string
	switch groupType {
	case scommon.GroupTypeProject:
		p, _, err := h.configstoreClient.GetProject(ctx, ref)
		if err != nil {
			return false, "", APIErrorFromRemoteError(err)
		}
		refID = p.ID
		ownerID = p.OwnerID
		ownerType = p.OwnerType
		visibility = p.GlobalVisibility
	case scommon.GroupTypeUser:
		u, _, err := h.configstoreClient.GetUser(ctx, ref)
		if err != nil {
			return false, "", APIErrorFromRemoteError(err)
		}

		// user direct runs
		refID = u.ID
		ownerType = cstypes.ObjectKindUser
		ownerID = u.ID
		visibility = cstypes.VisibilityPrivate
	}

	if visibility == cstypes.VisibilityPublic {
		return true, refID, nil
	}
	isProjectMember, err := h.IsAuthUserMember(ctx, ownerType, ownerID)
	if err != nil {
		return false, "", errors.Wrapf(err, "failed to determine ownership")
	}
	if !isProjectMember {
		return false, "", nil
	}
	return true, refID, nil
}

type actionType string

const (
	actionTypeRunAction  actionType = "runaction"
	actionTypeTaskAction actionType = "taskaction"
	actionTypeDeleteLogs actionType = "deletelogs"
)

func (h *ActionHandler) CanAuthUserDoRunActions(ctx context.Context, groupType scommon.GroupType, ref string, actionType actionType) (bool, string, error) {
	var ownerType cstypes.ObjectKind
	var refID string
	var ownerID string
	var p *csapitypes.Project
	switch groupType {
	case scommon.GroupTypeProject:
		var err error
		p, _, err = h.configstoreClient.GetProject(ctx, ref)
		if err != nil {
			return false, "", APIErrorFromRemoteError(err)
		}
		refID = p.ID
		ownerType = p.OwnerType
		ownerID = p.OwnerID
	case scommon.GroupTypeUser:
		u, _, err := h.configstoreClient.GetUser(ctx, ref)
		if err != nil {
			return false, "", APIErrorFromRemoteError(err)
		}

		// user direct runs
		refID = u.ID
		ownerType = cstypes.ObjectKindUser
		ownerID = u.ID
	}

	isProjectOwner, err := h.IsAuthUserProjectOwner(ctx, ownerType, ownerID)
	if err != nil {
		return false, "", errors.Wrapf(err, "failed to determine ownership")
	}
	if isProjectOwner {
		return true, refID, nil
	}

	if actionType == actionTypeRunAction && ownerType == cstypes.ObjectKindOrg {
		userID := common.CurrentUserID(ctx)
		isUserOrgMember, err := h.IsUserOrgMember(ctx, userID, ownerID)
		if err != nil {
			return false, "", errors.Wrapf(err, "failed to determine ownership")
		}
		if isUserOrgMember && p.MembersCanPerformRunActions {
			return true, refID, nil
		}
	}

	return false, "", nil
}

func (h *ActionHandler) IsUserOrgMember(ctx context.Context, userRef, orgRef string) (bool, error) {
	user, err := h.GetUser(ctx, userRef)
	if err != nil {
		return false, errors.Wrapf(err, "failed to get user %s:", userRef)
	}

	orgMembers, err := h.GetOrgMembers(ctx, &GetOrgMembersRequest{OrgRef: orgRef})
	if err != nil {
		return false, errors.Wrapf(err, "failed to get org %s members:", orgRef)
	}
	for _, member := range orgMembers.Members {
		if member.User.ID == user.ID {
			return true, nil
		}
	}

	return false, nil
}
