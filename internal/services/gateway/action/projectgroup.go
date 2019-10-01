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

	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"

	errors "golang.org/x/xerrors"
)

func (h *ActionHandler) GetProjectGroup(ctx context.Context, projectGroupRef string) (*csapitypes.ProjectGroup, error) {
	projectGroup, resp, err := h.configstoreClient.GetProjectGroup(ctx, projectGroupRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	return projectGroup, nil
}

func (h *ActionHandler) GetProjectGroupSubgroups(ctx context.Context, projectGroupRef string) ([]*csapitypes.ProjectGroup, error) {
	projectGroups, resp, err := h.configstoreClient.GetProjectGroupSubgroups(ctx, projectGroupRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	return projectGroups, nil
}

func (h *ActionHandler) GetProjectGroupProjects(ctx context.Context, projectGroupRef string) ([]*csapitypes.Project, error) {
	projects, resp, err := h.configstoreClient.GetProjectGroupProjects(ctx, projectGroupRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	return projects, nil
}

type CreateProjectGroupRequest struct {
	CurrentUserID string
	Name          string
	ParentRef     string
	Visibility    cstypes.Visibility
}

func (h *ActionHandler) CreateProjectGroup(ctx context.Context, req *CreateProjectGroupRequest) (*csapitypes.ProjectGroup, error) {
	if !util.ValidateName(req.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid projectGroup name %q", req.Name))
	}

	pg, resp, err := h.configstoreClient.GetProjectGroup(ctx, req.ParentRef)
	if err != nil {
		return nil, errors.Errorf("failed to get project group %q: %w", req.ParentRef, ErrFromRemote(resp, err))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, pg.OwnerType, pg.OwnerID)
	if err != nil {
		return nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	user, resp, err := h.configstoreClient.GetUser(ctx, req.CurrentUserID)
	if err != nil {
		return nil, errors.Errorf("failed to get user %q: %w", req.CurrentUserID, ErrFromRemote(resp, err))
	}

	parentRef := req.ParentRef
	if parentRef == "" {
		// create projectGroup in current user namespace
		parentRef = path.Join("user", user.Name)
	}

	p := &cstypes.ProjectGroup{
		Name: req.Name,
		Parent: cstypes.Parent{
			Type: cstypes.ConfigTypeProjectGroup,
			ID:   parentRef,
		},
		Visibility: req.Visibility,
	}

	h.log.Infof("creating projectGroup")
	rp, resp, err := h.configstoreClient.CreateProjectGroup(ctx, p)
	if err != nil {
		return nil, errors.Errorf("failed to create projectGroup: %w", ErrFromRemote(resp, err))
	}
	h.log.Infof("projectGroup %s created, ID: %s", rp.Name, rp.ID)

	return rp, nil
}

type UpdateProjectGroupRequest struct {
	Name      *string
	ParentRef *string

	Visibility *cstypes.Visibility
}

func (h *ActionHandler) UpdateProjectGroup(ctx context.Context, projectGroupRef string, req *UpdateProjectGroupRequest) (*csapitypes.ProjectGroup, error) {
	pg, resp, err := h.configstoreClient.GetProjectGroup(ctx, projectGroupRef)
	if err != nil {
		return nil, errors.Errorf("failed to get project group %q: %w", projectGroupRef, ErrFromRemote(resp, err))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, pg.OwnerType, pg.OwnerID)
	if err != nil {
		return nil, errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
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

	h.log.Infof("updating project group")
	rp, resp, err := h.configstoreClient.UpdateProjectGroup(ctx, pg.ID, pg.ProjectGroup)
	if err != nil {
		return nil, errors.Errorf("failed to update project group: %w", ErrFromRemote(resp, err))
	}
	h.log.Infof("project group %q updated, ID: %s", pg.Name, pg.ID)

	return rp, nil
}

func (h *ActionHandler) DeleteProjectGroup(ctx context.Context, projectRef string) error {
	p, resp, err := h.configstoreClient.GetProjectGroup(ctx, projectRef)
	if err != nil {
		return errors.Errorf("failed to get project %q: %w", projectRef, ErrFromRemote(resp, err))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, p.OwnerType, p.OwnerID)
	if err != nil {
		return errors.Errorf("failed to determine ownership: %w", err)
	}
	if !isProjectOwner {
		return util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	resp, err = h.configstoreClient.DeleteProjectGroup(ctx, projectRef)
	if err != nil {
		return ErrFromRemote(resp, err)
	}
	return nil
}
