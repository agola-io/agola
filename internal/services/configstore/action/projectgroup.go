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
	"agola.io/agola/internal/db"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	uuid "github.com/satori/go.uuid"
	errors "golang.org/x/xerrors"
)

func (h *ActionHandler) GetProjectGroup(ctx context.Context, projectGroupRef string) (*types.ProjectGroup, error) {
	var projectGroup *types.ProjectGroup
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		projectGroup, err = h.readDB.GetProjectGroup(tx, projectGroupRef)
		return err
	})
	if err != nil {
		return nil, err
	}

	if projectGroup == nil {
		return nil, util.NewErrNotExist(errors.Errorf("project group %q doesn't exist", projectGroupRef))
	}

	return projectGroup, nil
}

func (h *ActionHandler) GetProjectGroupSubgroups(ctx context.Context, projectGroupRef string) ([]*types.ProjectGroup, error) {
	var projectGroups []*types.ProjectGroup
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		projectGroup, err := h.readDB.GetProjectGroup(tx, projectGroupRef)
		if err != nil {
			return err
		}

		if projectGroup == nil {
			return util.NewErrNotExist(errors.Errorf("project group %q doesn't exist", projectGroupRef))
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
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		projectGroup, err := h.readDB.GetProjectGroup(tx, projectGroupRef)
		if err != nil {
			return err
		}

		if projectGroup == nil {
			return util.NewErrNotExist(errors.Errorf("project group %q doesn't exist", projectGroupRef))
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

	if projectGroup.Parent.Type != types.ConfigTypeProjectGroup {
		return nil, util.NewErrBadRequest(errors.Errorf("wrong project group parent type %q", projectGroup.Parent.Type))
	}

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		parentProjectGroup, err := h.readDB.GetProjectGroup(tx, projectGroup.Parent.ID)
		if err != nil {
			return err
		}
		if parentProjectGroup == nil {
			return util.NewErrBadRequest(errors.Errorf("project group with id %q doesn't exist", projectGroup.Parent.ID))
		}
		// TODO(sgotti) now we are doing a very ugly thing setting the request
		// projectgroup parent ID that can be both an ID or a ref. Then we are fixing
		// it to an ID here. Change the request format to avoid this.
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
		return nil, errors.Errorf("failed to marshal projectGroup: %w", err)
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
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		// check project exists
		pg, err := h.readDB.GetProjectGroup(tx, req.ProjectGroupRef)
		if err != nil {
			return err
		}
		if pg == nil {
			return util.NewErrBadRequest(errors.Errorf("project group with ref %q doesn't exist", req.ProjectGroupRef))
		}
		// check that the project group ID matches
		if pg.ID != req.ProjectGroup.ID {
			return util.NewErrBadRequest(errors.Errorf("project group with ref %q has a different id", req.ProjectGroupRef))
		}

		if pg.Parent.Type != req.ProjectGroup.Parent.Type {
			return util.NewErrBadRequest(errors.Errorf("changing project group parent type isn't supported"))
		}

		switch req.ProjectGroup.Parent.Type {
		case types.ConfigTypeOrg:
			fallthrough
		case types.ConfigTypeUser:
			// Cannot update root project group parent
			if pg.Parent.Type != req.ProjectGroup.Parent.Type || pg.Parent.ID != req.ProjectGroup.Parent.ID {
				return util.NewErrBadRequest(errors.Errorf("cannot change root project group parent type or id"))
			}
			// if the project group is a root project group force the name to be empty
			req.ProjectGroup.Name = ""

		case types.ConfigTypeProjectGroup:
			// check parent exists
			group, err := h.readDB.GetProjectGroup(tx, req.ProjectGroup.Parent.ID)
			if err != nil {
				return err
			}
			if group == nil {
				return util.NewErrBadRequest(errors.Errorf("project group with id %q doesn't exist", req.ProjectGroup.Parent.ID))
			}
			// TODO(sgotti) now we are doing a very ugly thing setting the request
			// projectgroup parent ID that can be both an ID or a ref. Then we are fixing
			// it to an ID here. Change the request format to avoid this.
			req.ProjectGroup.Parent.ID = group.ID
		}

		curPGParentPath, err := h.readDB.GetPath(tx, pg.Parent.Type, pg.Parent.ID)
		if err != nil {
			return err
		}
		curPGP := path.Join(curPGParentPath, pg.Name)

		pgParentPath, err := h.readDB.GetPath(tx, req.ProjectGroup.Parent.Type, req.ProjectGroup.Parent.ID)
		if err != nil {
			return err
		}
		pgp := path.Join(pgParentPath, req.ProjectGroup.Name)

		if pg.Name != req.ProjectGroup.Name || pg.Parent.ID != req.ProjectGroup.Parent.ID {
			// check duplicate project group name
			ap, err := h.readDB.GetProjectGroupByName(tx, req.ProjectGroup.Parent.ID, req.ProjectGroup.Name)
			if err != nil {
				return err
			}
			if ap != nil {
				return util.NewErrBadRequest(errors.Errorf("project group with name %q, path %q already exists", req.ProjectGroup.Name, pgp))
			}
			// Cannot move inside itself or a child project group
			if strings.HasPrefix(pgp, curPGP+"/") {
				return util.NewErrBadRequest(errors.Errorf("cannot move project group inside itself or child project group"))
			}
		}

		// changegroup is the project group path. Use "projectpath" prefix as it must
		// cover both projects and projectgroups
		cgNames := []string{util.EncodeSha256Hex("projectpath-" + pgp)}

		// add new projectpath
		if pg.Parent.ID != req.ProjectGroup.Parent.ID {
			cgNames = append(cgNames, util.EncodeSha256Hex("projectpath-"+pgp))
		}

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
		return nil, errors.Errorf("failed to marshal project: %w", err)
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
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error

		// check project group existance
		projectGroup, err = h.readDB.GetProjectGroup(tx, projectGroupRef)
		if err != nil {
			return err
		}
		if projectGroup == nil {
			return util.NewErrBadRequest(errors.Errorf("project group %q doesn't exist", projectGroupRef))
		}

		// cannot delete root project group
		if projectGroup.Parent.Type == types.ConfigTypeOrg ||
			projectGroup.Parent.Type == types.ConfigTypeUser {
			return util.NewErrBadRequest(errors.Errorf("cannot delete root project group"))
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
