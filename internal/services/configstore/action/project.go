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

func (h *ActionHandler) CreateProject(ctx context.Context, project *types.Project) (*types.Project, error) {
	if project.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("project name required"))
	}
	if !util.ValidateName(project.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid project name %q", project.Name))
	}
	if project.Parent.ID == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("project parent id required"))
	}
	if project.Parent.Type != types.ConfigTypeProjectGroup {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid project parent type %q", project.Parent.Type))
	}
	if !types.IsValidVisibility(project.Visibility) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid project visibility"))
	}
	if !types.IsValidRemoteRepositoryConfigType(project.RemoteRepositoryConfigType) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid project remote repository config type %q", project.RemoteRepositoryConfigType))
	}
	if project.RemoteRepositoryConfigType == types.RemoteRepositoryConfigTypeRemoteSource {
		if project.RemoteSourceID == "" {
			return nil, util.NewErrBadRequest(errors.Errorf("empty remote source id"))
		}
		if project.LinkedAccountID == "" {
			return nil, util.NewErrBadRequest(errors.Errorf("empty linked account id"))
		}
		if project.RepositoryID == "" {
			return nil, util.NewErrBadRequest(errors.Errorf("empty remote repository id"))
		}
		if project.RepositoryPath == "" {
			return nil, util.NewErrBadRequest(errors.Errorf("empty remote repository path"))
		}
	}

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		group, err := h.readDB.GetProjectGroup(tx, project.Parent.ID)
		if err != nil {
			return err
		}
		if group == nil {
			return util.NewErrBadRequest(errors.Errorf("project group with id %q doesn't exist", project.Parent.ID))
		}
		project.Parent.ID = group.ID

		groupPath, err := h.readDB.GetProjectGroupPath(tx, group)
		if err != nil {
			return err
		}
		pp := path.Join(groupPath, project.Name)

		// changegroup is the project path. Use "projectpath" prefix as it must
		// cover both projects and projectgroups
		cgNames := []string{util.EncodeSha256Hex("projectpath-" + pp)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check duplicate project name
		p, err := h.readDB.GetProjectByName(tx, project.Parent.ID, project.Name)
		if err != nil {
			return err
		}
		if p != nil {
			return util.NewErrBadRequest(errors.Errorf("project with name %q, path %q already exists", p.Name, pp))
		}
		// check duplicate project group name
		pg, err := h.readDB.GetProjectGroupByName(tx, project.Parent.ID, project.Name)
		if err != nil {
			return err
		}
		if pg != nil {
			return util.NewErrBadRequest(errors.Errorf("project group with name %q, path %q already exists", pg.Name, pp))
		}

		if project.RemoteRepositoryConfigType == types.RemoteRepositoryConfigTypeRemoteSource {
			// check that the linked account matches the remote source
			user, err := h.readDB.GetUserByLinkedAccount(tx, project.LinkedAccountID)
			if err != nil {
				return errors.Wrapf(err, "failed to get user with linked account id %q", project.LinkedAccountID)
			}
			if user == nil {
				return util.NewErrBadRequest(errors.Errorf("user for linked account %q doesn't exist", project.LinkedAccountID))
			}
			la, ok := user.LinkedAccounts[project.LinkedAccountID]
			if !ok {
				return util.NewErrBadRequest(errors.Errorf("linked account id %q for user %q doesn't exist", project.LinkedAccountID, user.Name))
			}
			if la.RemoteSourceID != project.RemoteSourceID {
				return util.NewErrBadRequest(errors.Errorf("linked account id %q remote source %q different than project remote source %q", project.LinkedAccountID, la.RemoteSourceID, project.RemoteSourceID))
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	project.ID = uuid.NewV4().String()
	project.Parent.Type = types.ConfigTypeProjectGroup
	project.Secret = util.EncodeSha1Hex(uuid.NewV4().String())

	pcj, err := json.Marshal(project)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal project")
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeProject),
			ID:         project.ID,
			Data:       pcj,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return project, err
}

func (h *ActionHandler) DeleteProject(ctx context.Context, projectRef string) error {
	var project *types.Project

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error

		// check project existance
		project, err = h.readDB.GetProject(tx, projectRef)
		if err != nil {
			return err
		}
		if project == nil {
			return util.NewErrBadRequest(errors.Errorf("project %q doesn't exist", projectRef))
		}

		// changegroup is the project id.
		cgNames := []string{util.EncodeSha256Hex(project.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	// TODO(sgotti) delete project secrets/variables
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypeDelete,
			DataType:   string(types.ConfigTypeProject),
			ID:         project.ID,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return err
}
