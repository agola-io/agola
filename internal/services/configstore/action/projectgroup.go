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
	"encoding/json"
	"path"
	"strings"

	"agola.io/agola/internal/datamanager"
	"agola.io/agola/internal/dbold"
	"agola.io/agola/internal/errors"

	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	"github.com/gofrs/uuid"
)

func (h *ActionHandler) GetProjectGroup(ctx context.Context, projectGroupRef string) (*types.ProjectGroup, error) {
	var projectGroup *types.ProjectGroup
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		projectGroup, err = h.readDB.GetProjectGroup(tx, projectGroupRef)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if projectGroup == nil {
		return nil, util.NewAPIError(util.ErrNotExist, errors.Errorf("project group %q doesn't exist", projectGroupRef))
	}

	return projectGroup, nil
}

func (h *ActionHandler) GetProjectGroupSubgroups(ctx context.Context, projectGroupRef string) ([]*types.ProjectGroup, error) {
	var projectGroups []*types.ProjectGroup
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		projectGroup, err := h.readDB.GetProjectGroup(tx, projectGroupRef)
		if err != nil {
			return errors.WithStack(err)
		}

		if projectGroup == nil {
			return util.NewAPIError(util.ErrNotExist, errors.Errorf("project group %q doesn't exist", projectGroupRef))
		}

		projectGroups, err = h.readDB.GetProjectGroupSubgroups(tx, projectGroup.ID)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return projectGroups, nil
}

func (h *ActionHandler) GetProjectGroupProjects(ctx context.Context, projectGroupRef string) ([]*types.Project, error) {
	var projects []*types.Project
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		projectGroup, err := h.readDB.GetProjectGroup(tx, projectGroupRef)
		if err != nil {
			return errors.WithStack(err)
		}

		if projectGroup == nil {
			return util.NewAPIError(util.ErrNotExist, errors.Errorf("project group %q doesn't exist", projectGroupRef))
		}

		projects, err = h.readDB.GetProjectGroupProjects(tx, projectGroup.ID)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return projects, nil
}

func (h *ActionHandler) ValidateProjectGroupReq(ctx context.Context, req *CreateUpdateProjectGroupRequest) error {
	if req.Parent.Type != types.ConfigTypeProjectGroup &&
		req.Parent.Type != types.ConfigTypeOrg &&
		req.Parent.Type != types.ConfigTypeUser {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid project group parent type %q", req.Parent.Type))
	}
	if req.Parent.ID == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group parent id required"))
	}

	// if the project group is a root project group the name must be empty
	if req.Parent.Type == types.ConfigTypeOrg ||
		req.Parent.Type == types.ConfigTypeUser {
		if req.Name != "" {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group name for root project group must be empty"))
		}
	} else {
		if req.Name == "" {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group name required"))
		}
		if !util.ValidateName(req.Name) {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid project group name %q", req.Name))
		}
	}
	if !types.IsValidVisibility(req.Visibility) {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid project group visibility"))
	}

	return nil
}

type CreateUpdateProjectGroupRequest struct {
	Name       string
	Parent     types.Parent
	Visibility types.Visibility
}

func (h *ActionHandler) CreateProjectGroup(ctx context.Context, req *CreateUpdateProjectGroupRequest) (*types.ProjectGroup, error) {
	if err := h.ValidateProjectGroupReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	if req.Parent.Type != types.ConfigTypeProjectGroup {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("wrong project group parent type %q", req.Parent.Type))
	}

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		parentProjectGroup, err := h.readDB.GetProjectGroup(tx, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		if parentProjectGroup == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group with id %q doesn't exist", req.Parent.ID))
		}
		// TODO(sgotti) now we are doing a very ugly thing setting the request
		// projectgroup parent ID that can be both an ID or a ref. Then we are fixing
		// it to an ID here. Change the request format to avoid this.
		req.Parent.ID = parentProjectGroup.ID

		groupPath, err := h.readDB.GetProjectGroupPath(tx, parentProjectGroup)
		if err != nil {
			return errors.WithStack(err)
		}
		pp := path.Join(groupPath, req.Name)

		// changegroup is the projectgroup path. Use "projectpath" prefix as it must
		// cover both projects and projectgroups
		cgNames := []string{util.EncodeSha256Hex("projectpath-" + pp)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return errors.WithStack(err)
		}

		// check duplicate project group name
		pg, err := h.readDB.GetProjectGroupByName(tx, req.Parent.ID, req.Name)
		if err != nil {
			return errors.WithStack(err)
		}
		if pg != nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group with name %q, path %q already exists", pg.Name, pp))
		}
		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	projectGroup := &types.ProjectGroup{}
	projectGroup.ID = uuid.Must(uuid.NewV4()).String()
	projectGroup.Name = req.Name
	projectGroup.Parent = req.Parent
	projectGroup.Visibility = req.Visibility

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
	return projectGroup, errors.WithStack(err)
}

type UpdateProjectGroupRequest struct {
	ProjectGroupRef string

	ProjectGroup *types.ProjectGroup
}

func (h *ActionHandler) UpdateProjectGroup(ctx context.Context, curProjectGroupRef string, req *CreateUpdateProjectGroupRequest) (*types.ProjectGroup, error) {
	if err := h.ValidateProjectGroupReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var cgt *datamanager.ChangeGroupsUpdateToken
	var projectGroup *types.ProjectGroup
	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		// check project exists
		projectGroup, err = h.readDB.GetProjectGroup(tx, curProjectGroupRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if projectGroup == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group with ref %q doesn't exist", curProjectGroupRef))
		}

		if projectGroup.Parent.Type != req.Parent.Type {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("changing project group parent type isn't supported"))
		}

		switch projectGroup.Parent.Type {
		case types.ConfigTypeOrg:
			fallthrough
		case types.ConfigTypeUser:
			// Cannot update root project group parent
			if projectGroup.Parent.Type != req.Parent.Type || projectGroup.Parent.ID != req.Parent.ID {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot change root project group parent type or id"))
			}
			// if the project group is a root project group force the name to be empty
			req.Name = ""

		case types.ConfigTypeProjectGroup:
			// check parent exists
			group, err := h.readDB.GetProjectGroup(tx, req.Parent.ID)
			if err != nil {
				return errors.WithStack(err)
			}
			if group == nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group with id %q doesn't exist", req.Parent.ID))
			}
			// TODO(sgotti) now we are doing a very ugly thing setting the request
			// projectgroup parent ID that can be both an ID or a ref. Then we are fixing
			// it to an ID here. Change the request format to avoid this.
			req.Parent.ID = group.ID
		}

		curPGParentPath, err := h.readDB.GetPath(tx, projectGroup.Parent.Type, projectGroup.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		curPGP := path.Join(curPGParentPath, projectGroup.Name)

		pgParentPath, err := h.readDB.GetPath(tx, req.Parent.Type, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		pgp := path.Join(pgParentPath, req.Name)

		if projectGroup.Name != req.Name || projectGroup.Parent.ID != req.Parent.ID {
			// check duplicate project group name
			ap, err := h.readDB.GetProjectGroupByName(tx, req.Parent.ID, req.Name)
			if err != nil {
				return errors.WithStack(err)
			}
			if ap != nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group with name %q, path %q already exists", req.Name, pgp))
			}
			// Cannot move inside itself or a child project group
			if strings.HasPrefix(pgp, curPGP+"/") {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot move project group inside itself or child project group"))
			}
		}

		// changegroup is the project group path. Use "projectpath" prefix as it must
		// cover both projects and projectgroups
		cgNames := []string{util.EncodeSha256Hex("projectpath-" + pgp)}

		// add new projectpath
		if projectGroup.Parent.ID != req.Parent.ID {
			cgNames = append(cgNames, util.EncodeSha256Hex("projectpath-"+pgp))
		}

		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// update current projectGroup
	projectGroup.Name = req.Name
	projectGroup.Parent = req.Parent
	projectGroup.Visibility = req.Visibility

	pgj, err := json.Marshal(projectGroup)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal project")
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
	return projectGroup, errors.WithStack(err)
}

func (h *ActionHandler) DeleteProjectGroup(ctx context.Context, projectGroupRef string) error {
	var projectGroup *types.ProjectGroup

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error

		// check project group existance
		projectGroup, err = h.readDB.GetProjectGroup(tx, projectGroupRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if projectGroup == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group %q doesn't exist", projectGroupRef))
		}

		// cannot delete root project group
		if projectGroup.Parent.Type == types.ConfigTypeOrg ||
			projectGroup.Parent.Type == types.ConfigTypeUser {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot delete root project group"))
		}

		// changegroup is the project group id.
		cgNames := []string{util.EncodeSha256Hex(projectGroup.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
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
	return errors.WithStack(err)
}
