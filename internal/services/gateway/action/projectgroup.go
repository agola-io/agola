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
	ParentID      string
	Visibility    types.Visibility
}

func (h *ActionHandler) CreateProjectGroup(ctx context.Context, req *CreateProjectGroupRequest) (*csapi.ProjectGroup, error) {
	if !util.ValidateName(req.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid projectGroup name %q", req.Name))
	}

	user, resp, err := h.configstoreClient.GetUser(ctx, req.CurrentUserID)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to get user %q", req.CurrentUserID))
	}

	parentID := req.ParentID
	if parentID == "" {
		// create projectGroup in current user namespace
		parentID = path.Join("user", user.Name)
	}

	p := &types.ProjectGroup{
		Name: req.Name,
		Parent: types.Parent{
			Type: types.ConfigTypeProjectGroup,
			ID:   parentID,
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
