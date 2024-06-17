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
	"path"

	"github.com/sorintlab/errors"

	serrors "agola.io/agola/internal/services/errors"
	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"
)

func (h *ActionHandler) GetProjectGroup(ctx context.Context, projectGroupRef string) (*csapitypes.ProjectGroup, error) {
	projectGroup, _, err := h.configstoreClient.GetProjectGroup(ctx, projectGroupRef)
	if err != nil {
		return nil, APIErrorFromRemoteError(err)
	}

	if projectGroup.GlobalVisibility == cstypes.VisibilityPublic {
		return projectGroup, nil
	}

	isMember, err := h.IsAuthUserMember(ctx, projectGroup.OwnerType, projectGroup.OwnerID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to determine ownership")
	}
	if !isMember {
		return nil, util.NewAPIError(util.ErrForbidden, util.WithAPIErrorMsg("user not authorized"))
	}

	return projectGroup, nil
}

func (h *ActionHandler) GetProjectGroupSubgroups(ctx context.Context, projectGroupRef string) ([]*csapitypes.ProjectGroup, error) {
	projectGroups, _, err := h.configstoreClient.GetProjectGroupSubgroups(ctx, projectGroupRef)
	if err != nil {
		return nil, APIErrorFromRemoteError(err)
	}
	return projectGroups, nil
}

func (h *ActionHandler) GetProjectGroupProjects(ctx context.Context, projectGroupRef string) ([]*csapitypes.Project, error) {
	projects, _, err := h.configstoreClient.GetProjectGroupProjects(ctx, projectGroupRef)
	if err != nil {
		return nil, APIErrorFromRemoteError(err)
	}
	return projects, nil
}

type CreateProjectGroupRequest struct {
	Name       string
	ParentRef  string
	Visibility cstypes.Visibility
}

func (h *ActionHandler) CreateProjectGroup(ctx context.Context, req *CreateProjectGroupRequest) (*csapitypes.ProjectGroup, error) {
	if !common.IsUserLogged(ctx) {
		return nil, util.NewAPIError(util.ErrForbidden, util.WithAPIErrorMsg("user not authenticated"))
	}
	curUserID := common.CurrentUserID(ctx)

	user, _, err := h.configstoreClient.GetUser(ctx, curUserID)
	if err != nil {
		return nil, APIErrorFromRemoteError(err, util.WithAPIErrorMsg("failed to get user %q", curUserID))
	}

	if !util.ValidateName(req.Name) {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("invalid project group name %q", req.Name), serrors.InvalidProjectName())
	}

	pg, _, err := h.configstoreClient.GetProjectGroup(ctx, req.ParentRef)
	if err != nil {
		if util.RemoteErrorIs(err, util.ErrNotExist) {
			return nil, util.NewAPIError(util.ErrNotExist, serrors.ParentProjectGroupDoesNotExist())
		}
		return nil, APIErrorFromRemoteError(err, util.WithAPIErrorMsg("failed to get parent project group %q", req.ParentRef))
	}

	isProjectOwner, err := h.IsAuthUserProjectOwner(ctx, pg.OwnerType, pg.OwnerID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to determine ownership")
	}
	if !isProjectOwner {
		return nil, util.NewAPIError(util.ErrForbidden, util.WithAPIErrorMsg("user not authorized"))
	}

	parentRef := req.ParentRef
	if parentRef == "" {
		// create projectGroup in current user namespace
		parentRef = path.Join("user", user.Name)
	}

	creq := &csapitypes.CreateUpdateProjectGroupRequest{
		Name: req.Name,
		Parent: cstypes.Parent{
			Kind: cstypes.ObjectKindProjectGroup,
			ID:   parentRef,
		},
		Visibility: req.Visibility,
	}

	h.log.Info().Msgf("creating projectGroup")
	rp, _, err := h.configstoreClient.CreateProjectGroup(ctx, creq)
	if err != nil {
		return nil, APIErrorFromRemoteError(err, util.WithAPIErrorMsg("failed to create project group"))
	}
	h.log.Info().Msgf("projectGroup %s created, ID: %s", rp.Name, rp.ID)

	return rp, nil
}

type UpdateProjectGroupRequest struct {
	Name      *string
	ParentRef *string

	Visibility *cstypes.Visibility
}

func (h *ActionHandler) UpdateProjectGroup(ctx context.Context, projectGroupRef string, req *UpdateProjectGroupRequest) (*csapitypes.ProjectGroup, error) {
	pg, _, err := h.configstoreClient.GetProjectGroup(ctx, projectGroupRef)
	if err != nil {
		return nil, APIErrorFromRemoteError(err, util.WithAPIErrorMsg("failed to get project group %q", projectGroupRef))
	}

	isProjectOwner, err := h.IsAuthUserProjectOwner(ctx, pg.OwnerType, pg.OwnerID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to determine ownership")
	}
	if !isProjectOwner {
		return nil, util.NewAPIError(util.ErrForbidden, util.WithAPIErrorMsg("user not authorized"))
	}

	if req.Name != nil {
		pg.Name = *req.Name
	}
	if req.ParentRef != nil {
		pg.Parent.ID = *req.ParentRef
	}
	if req.Visibility != nil {
		pg.Visibility = *req.Visibility
	}

	creq := &csapitypes.CreateUpdateProjectGroupRequest{
		Name:       pg.Name,
		Parent:     pg.Parent,
		Visibility: pg.Visibility,
	}

	h.log.Info().Msgf("updating project group")
	rp, _, err := h.configstoreClient.UpdateProjectGroup(ctx, pg.ID, creq)
	if err != nil {
		return nil, APIErrorFromRemoteError(err, util.WithAPIErrorMsg("failed to create project group"))
	}
	h.log.Info().Msgf("project group %q updated, ID: %s", pg.Name, pg.ID)

	return rp, nil
}

func (h *ActionHandler) DeleteProjectGroup(ctx context.Context, projectRef string) error {
	p, _, err := h.configstoreClient.GetProjectGroup(ctx, projectRef)
	if err != nil {
		return APIErrorFromRemoteError(err, util.WithAPIErrorMsg("failed to get project %q", projectRef))
	}

	isProjectOwner, err := h.IsAuthUserProjectOwner(ctx, p.OwnerType, p.OwnerID)
	if err != nil {
		return errors.Wrapf(err, "failed to determine ownership")
	}
	if !isProjectOwner {
		return util.NewAPIError(util.ErrForbidden, util.WithAPIErrorMsg("user not authorized"))
	}

	if _, err = h.configstoreClient.DeleteProjectGroup(ctx, projectRef); err != nil {
		return APIErrorFromRemoteError(err)
	}
	return nil
}
