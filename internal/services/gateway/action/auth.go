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

func (h *ActionHandler) userActionsForUser(ctx context.Context, userRef string) ([]cstypes.ActionType, error) {
	actions := []cstypes.ActionType{}

	userID := h.CurrentUserID(ctx)
	if userID == "" {
		return actions, nil
	}

	// By default any logged user can get an user
	actions = append(actions, cstypes.ActionTypeGetUser)

	// no existing user
	if userRef == "" {
		return actions, nil
	}

	user, resp, err := h.configstoreClient.GetUser(ctx, userRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}

	ownerActions, err := h.userActionsForOwner(ctx, cstypes.ConfigTypeUser, user.ID)
	if err != nil {
		return nil, err
	}
	actions = append(actions, ownerActions...)

	return actions, nil
}

func (h *ActionHandler) userActionsForOrg(ctx context.Context, orgRef string) ([]cstypes.ActionType, error) {
	actions := []cstypes.ActionType{}

	userID := h.CurrentUserID(ctx)
	if userID == "" {
		return actions, nil
	}

	// By default any logged user can create an org
	actions = append(actions, cstypes.ActionTypeCreateOrg)

	// no existing org
	if orgRef == "" {
		return actions, nil
	}

	org, resp, err := h.configstoreClient.GetOrg(ctx, orgRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}

	if org.Visibility == cstypes.VisibilityPublic {
		actions = append(actions, cstypes.OrgMemberActions...)
	}

	ownerRoles, err := h.userActionsForOwner(ctx, cstypes.ConfigTypeOrg, org.ID)
	if err != nil {
		return nil, err
	}
	actions = append(actions, ownerRoles...)

	return actions, nil
}

func (h *ActionHandler) userActionsForProjectGroup(ctx context.Context, projectGroupRef string) ([]cstypes.ActionType, error) {
	actions := []cstypes.ActionType{}

	userID := h.CurrentUserID(ctx)
	if userID == "" {
		return actions, nil
	}

	p, resp, err := h.configstoreClient.GetProjectGroup(ctx, projectGroupRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}

	if p.GlobalVisibility == cstypes.VisibilityPublic {
		actions = append(actions, cstypes.ProjectReadActions...)
	}

	ownerRoles, err := h.userActionsForOwner(ctx, p.OwnerType, p.OwnerID)
	if err != nil {
		return nil, err
	}
	actions = append(actions, ownerRoles...)

	return actions, nil
}

func (h *ActionHandler) userActionsForProject(ctx context.Context, projectRef string) ([]cstypes.ActionType, error) {
	actions := []cstypes.ActionType{}

	userID := h.CurrentUserID(ctx)
	if userID == "" {
		return actions, nil
	}

	p, resp, err := h.configstoreClient.GetProject(ctx, projectRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}

	if p.GlobalVisibility == cstypes.VisibilityPublic {
		actions = append(actions, cstypes.ProjectReadActions...)
	}
	ownerRoles, err := h.userActionsForOwner(ctx, p.OwnerType, p.OwnerID)
	if err != nil {
		return nil, err
	}
	actions = append(actions, ownerRoles...)

	return actions, nil
}

func (h *ActionHandler) userActionsForVariable(ctx context.Context, parentType cstypes.ConfigType, parentRef string) ([]cstypes.ActionType, error) {
	switch parentType {
	case cstypes.ConfigTypeProjectGroup:
		return h.userActionsForProjectGroup(ctx, parentRef)
	case cstypes.ConfigTypeProject:
		return h.userActionsForProject(ctx, parentRef)
	default:
		return nil, errors.Errorf("wrong parent type: %q", parentType)
	}
}

func (h *ActionHandler) userActionsForRun(ctx context.Context, runGroup string) ([]cstypes.ActionType, error) {
	actions := []cstypes.ActionType{}

	userID := h.CurrentUserID(ctx)
	if userID == "" {
		return actions, nil
	}

	groupType, groupID, err := common.GroupTypeIDFromRunGroup(runGroup)
	if err != nil {
		return nil, err
	}

	var visibility cstypes.Visibility
	var ownerType cstypes.ConfigType
	var ownerID string
	switch groupType {
	case common.GroupTypeProject:
		p, resp, err := h.configstoreClient.GetProject(ctx, groupID)
		if err != nil {
			return nil, ErrFromRemote(resp, err)
		}
		ownerType = p.OwnerType
		ownerID = p.OwnerID
		visibility = p.GlobalVisibility

	case common.GroupTypeUser:
		// user direct runs
		ownerType = cstypes.ConfigTypeUser
		ownerID = groupID
		visibility = cstypes.VisibilityPrivate
	default:
		return nil, errors.Errorf("wrong run group type: %q", runGroup)
	}

	if visibility == cstypes.VisibilityPublic {
		actions = append(actions, cstypes.ProjectReadActions...)
	}
	ownerRoles, err := h.userActionsForOwner(ctx, ownerType, ownerID)
	if err != nil {
		return nil, err
	}
	actions = append(actions, ownerRoles...)

	return actions, nil
}

func (h *ActionHandler) userActionsForOwner(ctx context.Context, ownerType cstypes.ConfigType, ownerID string) ([]cstypes.ActionType, error) {
	actions := []cstypes.ActionType{}

	userID := h.CurrentUserID(ctx)
	if userID == "" {
		return actions, nil
	}

	switch ownerType {
	case cstypes.ConfigTypeUser:
		if userID == ownerID {
			actions = append(actions, cstypes.UserOwnerActions...)
		}
	case cstypes.ConfigTypeOrg:
		userOrgs, resp, err := h.configstoreClient.GetUserOrgs(ctx, userID)
		if err != nil {
			return nil, errors.Errorf("failed to get user orgs: %w", ErrFromRemote(resp, err))
		}

		for _, userOrg := range userOrgs {
			if userOrg.Organization.ID != ownerID {
				continue
			}
			if userOrg.Role == cstypes.OrgMemberRoleOwner {
				actions = append(actions, cstypes.OrgOwnerActions...)
			}
			if userOrg.Role == cstypes.OrgMemberRoleMember {
				actions = append(actions, cstypes.OrgMemberActions...)
			}
		}
	}

	return actions, nil
}

func (h *ActionHandler) CanDoUserAction(ctx context.Context, action cstypes.ActionType, userRef string) (bool, error) {
	actions, err := h.userActionsForUser(ctx, userRef)
	if err != nil {
		return false, err
	}

	return h.CanDoAction(ctx, actions, action)
}

func (h *ActionHandler) CanDoOrgAction(ctx context.Context, action cstypes.ActionType, orgRef string) (bool, error) {
	actions, err := h.userActionsForOrg(ctx, orgRef)
	if err != nil {
		return false, err
	}

	return h.CanDoAction(ctx, actions, action)
}

func (h *ActionHandler) CanDoProjectGroupAction(ctx context.Context, action cstypes.ActionType, projectGroupRef string) (bool, error) {
	actions, err := h.userActionsForProjectGroup(ctx, projectGroupRef)
	if err != nil {
		return false, err
	}

	return h.CanDoAction(ctx, actions, action)
}

func (h *ActionHandler) CanDoProjectAction(ctx context.Context, action cstypes.ActionType, projectRef string) (bool, error) {
	actions, err := h.userActionsForProject(ctx, projectRef)
	if err != nil {
		return false, err
	}

	return h.CanDoAction(ctx, actions, action)
}

func (h *ActionHandler) CanDoVariableAction(ctx context.Context, action cstypes.ActionType, parentType cstypes.ConfigType, parentRef string) (bool, error) {
	actions, err := h.userActionsForVariable(ctx, parentType, parentRef)
	if err != nil {
		return false, err
	}

	return h.CanDoAction(ctx, actions, action)
}
func (h *ActionHandler) CanDoSecretAction(ctx context.Context, action cstypes.ActionType, parentType cstypes.ConfigType, parentRef string) (bool, error) {
	return h.CanDoVariableAction(ctx, action, parentType, parentRef)
}

func (h *ActionHandler) CanDoRunAction(ctx context.Context, action cstypes.ActionType, runGroup string) (bool, error) {
	actions, err := h.userActionsForRun(ctx, runGroup)
	if err != nil {
		return false, err
	}

	return h.CanDoAction(ctx, actions, action)
}

func (h *ActionHandler) CanDoAction(ctx context.Context, actions []cstypes.ActionType, action cstypes.ActionType) (bool, error) {
	isAdmin := h.IsUserAdmin(ctx)
	if isAdmin {
		actions = append(actions, cstypes.AdminActions...)
	}

	for _, a := range actions {
		if a != action {
			continue
		}
		return true, nil
	}

	return false, nil
}
