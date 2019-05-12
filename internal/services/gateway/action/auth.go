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

package action

import (
	"context"

	"github.com/sorintlab/agola/internal/services/gateway/common"
	"github.com/sorintlab/agola/internal/services/types"

	"github.com/pkg/errors"
)

func (h *ActionHandler) CurrentUserID(ctx context.Context) string {
	userIDVal := ctx.Value("userid")
	if userIDVal == nil {
		return ""
	}
	return userIDVal.(string)
}

func (h *ActionHandler) IsUserLogged(ctx context.Context) bool {
	return ctx.Value("userid") != nil
}

func (h *ActionHandler) IsUserAdmin(ctx context.Context) bool {
	isAdmin := false
	isAdminVal := ctx.Value("admin")
	if isAdminVal != nil {
		isAdmin = isAdminVal.(bool)
	}
	return isAdmin
}

func (h *ActionHandler) IsUserLoggedOrAdmin(ctx context.Context) bool {
	return h.IsUserLogged(ctx) || h.IsUserAdmin(ctx)
}

func (h *ActionHandler) IsOrgOwner(ctx context.Context, orgID string) (bool, error) {
	isAdmin := h.IsUserAdmin(ctx)
	if isAdmin {
		return true, nil
	}

	userID := h.CurrentUserID(ctx)
	if userID == "" {
		return false, nil
	}

	userOrgs, resp, err := h.configstoreClient.GetUserOrgs(ctx, userID)
	if err != nil {
		return false, ErrFromRemote(resp, errors.Wrapf(err, "failed to get user orgs"))
	}

	for _, userOrg := range userOrgs {
		if userOrg.Organization.ID != orgID {
			continue
		}
		if userOrg.Role == types.MemberRoleOwner {
			return true, nil
		}
	}

	return false, nil
}

func (h *ActionHandler) IsProjectOwner(ctx context.Context, ownerType types.ConfigType, ownerID string) (bool, error) {
	isAdmin := h.IsUserAdmin(ctx)
	if isAdmin {
		return true, nil
	}

	userID := h.CurrentUserID(ctx)
	if userID == "" {
		return false, nil
	}

	if ownerType == types.ConfigTypeUser {
		if userID == ownerID {
			return true, nil
		}
	}

	if ownerType == types.ConfigTypeOrg {
		userOrgs, resp, err := h.configstoreClient.GetUserOrgs(ctx, userID)
		if err != nil {
			return false, ErrFromRemote(resp, errors.Wrapf(err, "failed to get user orgs"))
		}

		for _, userOrg := range userOrgs {
			if userOrg.Organization.ID != ownerID {
				continue
			}
			if userOrg.Role == types.MemberRoleOwner {
				return true, nil
			}
		}
	}

	return false, nil
}

func (h *ActionHandler) IsProjectMember(ctx context.Context, ownerType types.ConfigType, ownerID string) (bool, error) {
	isAdmin := h.IsUserAdmin(ctx)
	if isAdmin {
		return true, nil
	}

	userID := h.CurrentUserID(ctx)
	if userID == "" {
		return false, nil
	}

	if ownerType == types.ConfigTypeUser {
		if userID == ownerID {
			return true, nil
		}
	}

	if ownerType == types.ConfigTypeOrg {
		userOrgs, resp, err := h.configstoreClient.GetUserOrgs(ctx, userID)
		if err != nil {
			return false, ErrFromRemote(resp, errors.Wrapf(err, "failed to get user orgs"))
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

func (h *ActionHandler) IsVariableOwner(ctx context.Context, parentType types.ConfigType, parentRef string) (bool, error) {
	var ownerType types.ConfigType
	var ownerID string
	switch parentType {
	case types.ConfigTypeProjectGroup:
		pg, resp, err := h.configstoreClient.GetProjectGroup(ctx, parentRef)
		if err != nil {
			return false, ErrFromRemote(resp, errors.Wrapf(err, "failed to get project group %q", parentRef))
		}
		ownerType = pg.OwnerType
		ownerID = pg.OwnerID
	case types.ConfigTypeProject:
		p, resp, err := h.configstoreClient.GetProject(ctx, parentRef)
		if err != nil {
			return false, ErrFromRemote(resp, errors.Wrapf(err, "failed to get project  %q", parentRef))
		}
		ownerType = p.OwnerType
		ownerID = p.OwnerID
	}

	return h.IsProjectOwner(ctx, ownerType, ownerID)
}

func (h *ActionHandler) CanGetRun(ctx context.Context, runGroup string) (bool, error) {
	groupType, groupID, err := common.GroupTypeIDFromRunGroup(runGroup)
	if err != nil {
		return false, err
	}

	var visibility types.Visibility
	var ownerType types.ConfigType
	var ownerID string
	switch groupType {
	case common.GroupTypeProject:
		p, resp, err := h.configstoreClient.GetProject(ctx, groupID)
		if err != nil {
			return false, ErrFromRemote(resp, err)
		}
		ownerType = p.OwnerType
		ownerID = p.OwnerID
		visibility = p.GlobalVisibility
	case common.GroupTypeUser:
		// user local runs
		ownerType = types.ConfigTypeUser
		ownerID = groupID
		visibility = types.VisibilityPrivate
	}

	isProjectMember, err := h.IsProjectMember(ctx, ownerType, ownerID)
	if err != nil {
		return false, errors.Wrapf(err, "failed to determine ownership")
	}
	if visibility == types.VisibilityPublic {
		return true, nil
	}
	if !isProjectMember {
		return false, nil
	}
	return true, nil
}

func (h *ActionHandler) CanDoRunActions(ctx context.Context, runGroup string) (bool, error) {
	groupType, groupID, err := common.GroupTypeIDFromRunGroup(runGroup)
	if err != nil {
		return false, err
	}

	var ownerType types.ConfigType
	var ownerID string
	switch groupType {
	case common.GroupTypeProject:
		p, resp, err := h.configstoreClient.GetProject(ctx, groupID)
		if err != nil {
			return false, ErrFromRemote(resp, err)
		}
		ownerType = p.OwnerType
		ownerID = p.OwnerID
	case common.GroupTypeUser:
		// user local runs
		ownerType = types.ConfigTypeUser
		ownerID = groupID
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, ownerType, ownerID)
	if err != nil {
		return false, errors.Wrapf(err, "failed to determine ownership")
	}
	if !isProjectOwner {
		return false, nil
	}
	return true, nil
}
