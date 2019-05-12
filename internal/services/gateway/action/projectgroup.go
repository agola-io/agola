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

	csapi "github.com/sorintlab/agola/internal/services/configstore/api"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
)

func (h *ActionHandler) GetProjectGroup(ctx context.Context, projectGroupRef string) (*csapi.ProjectGroup, error) {
	projectGroup, resp, err := h.configstoreClient.GetProjectGroup(ctx, projectGroupRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	return projectGroup, nil
}

func (h *ActionHandler) GetProjectGroupSubgroups(ctx context.Context, projectGroupRef string) ([]*csapi.ProjectGroup, error) {
	projectGroups, resp, err := h.configstoreClient.GetProjectGroupSubgroups(ctx, projectGroupRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	return projectGroups, nil
}

func (h *ActionHandler) GetProjectGroupProjects(ctx context.Context, projectGroupRef string) ([]*csapi.Project, error) {
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
	Visibility    types.Visibility
}

func (h *ActionHandler) CreateProjectGroup(ctx context.Context, req *CreateProjectGroupRequest) (*csapi.ProjectGroup, error) {
	if !util.ValidateName(req.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid projectGroup name %q", req.Name))
	}

	pg, resp, err := h.configstoreClient.GetProjectGroup(ctx, req.ParentRef)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to get project group %q", req.ParentRef))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, pg.OwnerType, pg.OwnerID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to determine ownership")
	}
	if !isProjectOwner {
		return nil, util.NewErrForbidden(errors.Errorf("user not authorized"))
	}

	user, resp, err := h.configstoreClient.GetUser(ctx, req.CurrentUserID)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to get user %q", req.CurrentUserID))
	}

	parentRef := req.ParentRef
	if parentRef == "" {
		// create projectGroup in current user namespace
		parentRef = path.Join("user", user.Name)
	}

	p := &types.ProjectGroup{
		Name: req.Name,
		Parent: types.Parent{
			Type: types.ConfigTypeProjectGroup,
			ID:   parentRef,
		},
		Visibility: req.Visibility,
	}

	h.log.Infof("creating projectGroup")
	rp, resp, err := h.configstoreClient.CreateProjectGroup(ctx, p)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to create projectGroup"))
	}
	h.log.Infof("projectGroup %s created, ID: %s", rp.Name, rp.ID)

	return rp, nil
}

func (h *ActionHandler) DeleteProjectGroup(ctx context.Context, projectRef string) error {
	p, resp, err := h.configstoreClient.GetProjectGroup(ctx, projectRef)
	if err != nil {
		return ErrFromRemote(resp, errors.Wrapf(err, "failed to get project %q", projectRef))
	}

	isProjectOwner, err := h.IsProjectOwner(ctx, p.OwnerType, p.OwnerID)
	if err != nil {
		return errors.Wrapf(err, "failed to determine ownership")
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
