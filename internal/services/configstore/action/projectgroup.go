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
	"encoding/json"
	"path"

	"github.com/sorintlab/agola/internal/datamanager"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func (h *ActionHandler) GetProjectGroupSubgroups(ctx context.Context, projectGroupRef string) ([]*types.ProjectGroup, error) {
	var projectGroups []*types.ProjectGroup
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		projectGroup, err := h.readDB.GetProjectGroup(tx, projectGroupRef)
		if err != nil {
			return err
		}

		if projectGroup == nil {
			return util.NewErrNotFound(errors.Errorf("project group %q doesn't exist", projectGroupRef))
		}

		projectGroups, err = h.readDB.GetProjectGroupSubgroups(tx, projectGroup.ID)
		return err
	})
	if err != nil {
		return nil, err
	}

	return projectGroups, nil
}

func (h *ActionHandler) GetProjectGroupProjects(ctx context.Context, projectGroupRef string) ([]*types.Project, error) {
	var projects []*types.Project
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		projectGroup, err := h.readDB.GetProjectGroup(tx, projectGroupRef)
		if err != nil {
			return err
		}

		if projectGroup == nil {
			return util.NewErrNotFound(errors.Errorf("project group %q doesn't exist", projectGroupRef))
		}

		projects, err = h.readDB.GetProjectGroupProjects(tx, projectGroup.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return projects, nil
}

func (h *ActionHandler) ValidateProjectGroup(ctx context.Context, projectGroup *types.ProjectGroup) error {
	if projectGroup.Parent.Type != types.ConfigTypeProjectGroup &&
		projectGroup.Parent.Type != types.ConfigTypeOrg &&
		projectGroup.Parent.Type != types.ConfigTypeUser {
		return util.NewErrBadRequest(errors.Errorf("invalid project group parent type %q", projectGroup.Parent.Type))
	}
	if projectGroup.Parent.ID == "" {
		return util.NewErrBadRequest(errors.Errorf("project group parent id required"))
	}

	// if the project group is a root project group the name must be empty
	if projectGroup.Parent.Type == types.ConfigTypeOrg ||
		projectGroup.Parent.Type == types.ConfigTypeUser {
		if projectGroup.Name != "" {
			return util.NewErrBadRequest(errors.Errorf("project group name for root project group must be empty"))
		}
	} else {
		if projectGroup.Name == "" {
			return util.NewErrBadRequest(errors.Errorf("project group name required"))
		}
		if !util.ValidateName(projectGroup.Name) {
			return util.NewErrBadRequest(errors.Errorf("invalid project group name %q", projectGroup.Name))
		}
	}
	if !types.IsValidVisibility(projectGroup.Visibility) {
		return util.NewErrBadRequest(errors.Errorf("invalid project group visibility"))
	}

	return nil
}

func (h *ActionHandler) CreateProjectGroup(ctx context.Context, projectGroup *types.ProjectGroup) (*types.ProjectGroup, error) {
	if err := h.ValidateProjectGroup(ctx, projectGroup); err != nil {
		return nil, err
	}

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(func(tx *db.Tx) error {
		parentProjectGroup, err := h.readDB.GetProjectGroup(tx, projectGroup.Parent.ID)
		if err != nil {
			return err
		}
		if parentProjectGroup == nil {
			return util.NewErrBadRequest(errors.Errorf("project group with id %q doesn't exist", projectGroup.Parent.ID))
		}
		projectGroup.Parent.ID = parentProjectGroup.ID

		groupPath, err := h.readDB.GetProjectGroupPath(tx, parentProjectGroup)
		if err != nil {
			return err
		}
		pp := path.Join(groupPath, projectGroup.Name)

		// changegroup is the projectgroup path. Use "projectpath" prefix as it must
		// cover both projects and projectgroups
		cgNames := []string{util.EncodeSha256Hex("projectpath-" + pp)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check duplicate project name
		p, err := h.readDB.GetProjectByName(tx, projectGroup.Parent.ID, projectGroup.Name)
		if err != nil {
			return err
		}
		if p != nil {
			return util.NewErrBadRequest(errors.Errorf("project with name %q, path %q already exists", p.Name, pp))
		}
		// check duplicate project group name
		pg, err := h.readDB.GetProjectGroupByName(tx, projectGroup.Parent.ID, projectGroup.Name)
		if err != nil {
			return err
		}
		if pg != nil {
			return util.NewErrBadRequest(errors.Errorf("project group with name %q, path %q already exists", pg.Name, pp))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	projectGroup.ID = uuid.NewV4().String()
	projectGroup.Parent.Type = types.ConfigTypeProjectGroup

	pgj, err := json.Marshal(projectGroup)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal projectGroup")
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeProjectGroup),
			ID:         projectGroup.ID,
			Data:       pgj,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return projectGroup, err
}

type UpdateProjectGroupRequest struct {
	ProjectGroupRef string

	ProjectGroup *types.ProjectGroup
}

func (h *ActionHandler) UpdateProjectGroup(ctx context.Context, req *UpdateProjectGroupRequest) (*types.ProjectGroup, error) {
	if err := h.ValidateProjectGroup(ctx, req.ProjectGroup); err != nil {
		return nil, err
	}

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		// check project exists
		pg, err := h.readDB.GetProjectGroup(tx, req.ProjectGroupRef)
		if err != nil {
			return err
		}
		if pg == nil {
			return util.NewErrBadRequest(errors.Errorf("project group with ref %q doesn't exist", req.ProjectGroupRef))
		}
		// check that the project.ID matches
		if pg.ID != req.ProjectGroup.ID {
			return util.NewErrBadRequest(errors.Errorf("project group with ref %q has a different id", req.ProjectGroupRef))
		}

		// check parent exists
		switch pg.Parent.Type {
		case types.ConfigTypeProjectGroup:
			group, err := h.readDB.GetProjectGroup(tx, req.ProjectGroup.Parent.ID)
			if err != nil {
				return err
			}
			if group == nil {
				return util.NewErrBadRequest(errors.Errorf("project group with id %q doesn't exist", req.ProjectGroup.Parent.ID))
			}
		}

		// currently we don't support changing parent
		// TODO(sgotti) handle project move (changed parent project group)
		if pg.Parent.Type != req.ProjectGroup.Parent.Type {
			return util.NewErrBadRequest(errors.Errorf("changing project group parent isn't supported"))
		}
		if pg.Parent.ID != req.ProjectGroup.Parent.ID {
			return util.NewErrBadRequest(errors.Errorf("changing project group parent isn't supported"))
		}

		// if the project group is a root project group force the name to be empty
		if pg.Parent.Type == types.ConfigTypeOrg ||
			pg.Parent.Type == types.ConfigTypeUser {
			req.ProjectGroup.Name = ""
		}

		pgp, err := h.readDB.GetProjectGroupPath(tx, pg)
		if err != nil {
			return err
		}

		// changegroup is the project group path. Use "projectpath" prefix as it must
		// cover both projects and projectgroups
		cgNames := []string{util.EncodeSha256Hex("projectpath-" + pgp)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	pgj, err := json.Marshal(req.ProjectGroup)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal project")
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeProjectGroup),
			ID:         req.ProjectGroup.ID,
			Data:       pgj,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return req.ProjectGroup, err
}

func (h *ActionHandler) DeleteProjectGroup(ctx context.Context, projectGroupRef string) error {
	var projectGroup *types.ProjectGroup

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error

		// check project group existance
		projectGroup, err = h.readDB.GetProjectGroup(tx, projectGroupRef)
		if err != nil {
			return err
		}
		if projectGroup == nil {
			return util.NewErrBadRequest(errors.Errorf("project group %q doesn't exist", projectGroupRef))
		}

		// changegroup is the project group id.
		cgNames := []string{util.EncodeSha256Hex(projectGroup.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	// TODO(sgotti) implement childs garbage collection
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypeDelete,
			DataType:   string(types.ConfigTypeProjectGroup),
			ID:         projectGroup.ID,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return err
}
