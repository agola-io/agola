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

	"agola.io/agola/internal/errors"
	scommon "agola.io/agola/internal/services/common"
	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/util"
	cstypes "agola.io/agola/services/configstore/types"
)

func (h *ActionHandler) IsOrgOwner(ctx context.Context, orgID string) (bool, error) {
	isAdmin := common.IsUserAdmin(ctx)
	if isAdmin {
		return true, nil
	}

	userID := common.CurrentUserID(ctx)
	if userID == "" {
		return false, nil
	}

	userOrgs, _, err := h.configstoreClient.GetUserOrgs(ctx, userID)
	if err != nil {
		return false, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user orgs"))
	}

	for _, userOrg := range userOrgs {
		if userOrg.Organization.ID != orgID {
			continue
		}
		if userOrg.Role == cstypes.MemberRoleOwner {
			return true, nil
		}
	}

	return false, nil
}

func (h *ActionHandler) IsProjectOwner(ctx context.Context, ownerType cstypes.ConfigType, ownerID string) (bool, error) {
	isAdmin := common.IsUserAdmin(ctx)
	if isAdmin {
		return true, nil
	}

	userID := common.CurrentUserID(ctx)
	if userID == "" {
		return false, nil
	}

	if ownerType == cstypes.ConfigTypeUser {
		if userID == ownerID {
			return true, nil
		}
	}

	if ownerType == cstypes.ConfigTypeOrg {
		userOrgs, _, err := h.configstoreClient.GetUserOrgs(ctx, userID)
		if err != nil {
			return false, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user orgs"))
		}

		for _, userOrg := range userOrgs {
			if userOrg.Organization.ID != ownerID {
				continue
			}
			if userOrg.Role == cstypes.MemberRoleOwner {
				return true, nil
			}
		}
	}

	return false, nil
}

func (h *ActionHandler) IsProjectMember(ctx context.Context, ownerType cstypes.ConfigType, ownerID string) (bool, error) {
	isAdmin := common.IsUserAdmin(ctx)
	if isAdmin {
		return true, nil
	}

	userID := common.CurrentUserID(ctx)
	if userID == "" {
		return false, nil
	}

	if ownerType == cstypes.ConfigTypeUser {
		if userID == ownerID {
			return true, nil
		}
	}

	if ownerType == cstypes.ConfigTypeOrg {
		userOrgs, _, err := h.configstoreClient.GetUserOrgs(ctx, userID)
		if err != nil {
			return false, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get user orgs"))
		}

		for _, userOrg := range userOrgs {
			if userOrg.Organization.ID != ownerID {
				continue
			}
			return true, nil
		}
	}

	return false, nil
}

func (h *ActionHandler) IsVariableOwner(ctx context.Context, parentType cstypes.ConfigType, parentRef string) (bool, error) {
	var ownerType cstypes.ConfigType
	var ownerID string
	switch parentType {
	case cstypes.ConfigTypeProjectGroup:
		pg, _, err := h.configstoreClient.GetProjectGroup(ctx, parentRef)
		if err != nil {
			return false, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get project group %q", parentRef))
		}
		ownerType = pg.OwnerType
		ownerID = pg.OwnerID
	case cstypes.ConfigTypeProject:
		p, _, err := h.configstoreClient.GetProject(ctx, parentRef)
		if err != nil {
			return false, util.NewAPIError(util.KindFromRemoteError(err), errors.Wrapf(err, "failed to get project  %q", parentRef))
		}
		ownerType = p.OwnerType
		ownerID = p.OwnerID
	}

	return h.IsProjectOwner(ctx, ownerType, ownerID)
}

func (h *ActionHandler) CanGetRun(ctx context.Context, groupType scommon.GroupType, ref string) (bool, string, error) {
	var visibility cstypes.Visibility
	var ownerType cstypes.ConfigType
	var refID string
	var ownerID string
	switch groupType {
	case scommon.GroupTypeProject:
		p, _, err := h.configstoreClient.GetProject(ctx, ref)
		if err != nil {
			return false, "", util.NewAPIError(util.KindFromRemoteError(err), err)
		}
		refID = p.ID
		ownerID = p.OwnerID
		ownerType = p.OwnerType
		visibility = p.GlobalVisibility
	case scommon.GroupTypeUser:
		u, _, err := h.configstoreClient.GetUser(ctx, ref)
		if err != nil {
			return false, "", util.NewAPIError(util.KindFromRemoteError(err), err)
		}

		// user direct runs
		refID = u.ID
		ownerType = cstypes.ConfigTypeUser
		ownerID = u.ID
		visibility = cstypes.VisibilityPrivate
	}

	if visibility == cstypes.VisibilityPublic {
		return true, refID, nil
	}
	isProjectMember, err := h.IsProjectMember(ctx, ownerType, ownerID)
	if err != nil {
		return false, "", errors.Wrapf(err, "failed to determine ownership")
	}
	if !isProjectMember {
		return false, "", nil
	}
	return true, refID, nil
}

func (h *ActionHandler) CanDoRunActions(ctx context.Context, groupType scommon.GroupType, ref string) (bool, string, error) {
	var ownerType cstypes.ConfigType
	var refID string
	var ownerID string
	switch groupType {
	case scommon.GroupTypeProject:
		p, _, err := h.configstoreClient.GetProject(ctx, ref)
		if err != nil {
			return false, "", util.NewAPIError(util.KindFromRemoteError(err), err)
		}
		refID = p.ID
		ownerType = p.OwnerType
		ownerID = p.OwnerID
	case scommon.GroupTypeUser:
		u, _, err := h.configstoreClient.GetUser(ctx, ref)
		if err != nil {
			return false, "", util.NewAPIError(util.KindFromRemoteError(err), err)
		}

		// user direct runs
		refID = u.ID
		ownerType = cstypes.ConfigTypeUser
		ownerID = u.ID
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, ownerType, ownerID)
	if err != nil {
		return false, "", errors.Wrapf(err, "failed to determine ownership")
	}
	if !isProjectOwner {
		return false, "", nil
	}
	return true, refID, nil
}
