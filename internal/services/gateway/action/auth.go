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

	"agola.io/agola/internal/services/common"
	cstypes "agola.io/agola/services/configstore/types"

	errors "golang.org/x/xerrors"
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
		return false, errors.Errorf("failed to get user orgs: %w", ErrFromRemote(resp, err))
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
	isAdmin := h.IsUserAdmin(ctx)
	if isAdmin {
		return true, nil
	}

	userID := h.CurrentUserID(ctx)
	if userID == "" {
		return false, nil
	}

	if ownerType == cstypes.ConfigTypeUser {
		if userID == ownerID {
			return true, nil
		}
	}

	if ownerType == cstypes.ConfigTypeOrg {
		userOrgs, resp, err := h.configstoreClient.GetUserOrgs(ctx, userID)
		if err != nil {
			return false, errors.Errorf("failed to get user orgs: %w", ErrFromRemote(resp, err))
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
	isAdmin := h.IsUserAdmin(ctx)
	if isAdmin {
		return true, nil
	}

	userID := h.CurrentUserID(ctx)
	if userID == "" {
		return false, nil
	}

	if ownerType == cstypes.ConfigTypeUser {
		if userID == ownerID {
			return true, nil
		}
	}

	if ownerType == cstypes.ConfigTypeOrg {
		userOrgs, resp, err := h.configstoreClient.GetUserOrgs(ctx, userID)
		if err != nil {
			return false, errors.Errorf("failed to get user orgs: %w", ErrFromRemote(resp, err))
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
		pg, resp, err := h.configstoreClient.GetProjectGroup(ctx, parentRef)
		if err != nil {
			return false, errors.Errorf("failed to get project group %q: %w", parentRef, ErrFromRemote(resp, err))
		}
		ownerType = pg.OwnerType
		ownerID = pg.OwnerID
	case cstypes.ConfigTypeProject:
		p, resp, err := h.configstoreClient.GetProject(ctx, parentRef)
		if err != nil {
			return false, errors.Errorf("failed to get project  %q: %w", parentRef, ErrFromRemote(resp, err))
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

	var visibility cstypes.Visibility
	var ownerType cstypes.ConfigType
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
		// user direct runs
		ownerType = cstypes.ConfigTypeUser
		ownerID = groupID
		visibility = cstypes.VisibilityPrivate
	}

	if visibility == cstypes.VisibilityPublic {
		return true, nil
	}
	isProjectMember, err := h.IsProjectMember(ctx, ownerType, ownerID)
	if err != nil {
		return false, errors.Errorf("failed to determine ownership: %w", err)
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

	var ownerType cstypes.ConfigType
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
		// user direct runs
		ownerType = cstypes.ConfigTypeUser
		ownerID = groupID
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, ownerType, ownerID)
	if err != nil {
		return false, errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return false, nil
	}
	return true, nil
}
