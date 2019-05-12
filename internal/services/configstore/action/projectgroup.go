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

func (h *ActionHandler) CreateProjectGroup(ctx context.Context, projectGroup *types.ProjectGroup) (*types.ProjectGroup, error) {
	if projectGroup.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("project group name required"))
	}
	if !util.ValidateName(projectGroup.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid project group name %q", projectGroup.Name))
	}
	if projectGroup.Parent.ID == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("project group parent id required"))
	}
	if !types.IsValidVisibility(projectGroup.Visibility) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid project group visibility"))
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

	pcj, err := json.Marshal(projectGroup)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal projectGroup")
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeProjectGroup),
			ID:         projectGroup.ID,
			Data:       pcj,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return projectGroup, err
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
