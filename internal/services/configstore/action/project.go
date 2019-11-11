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

	"agola.io/agola/internal/datamanager"
	"agola.io/agola/internal/db"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	uuid "github.com/satori/go.uuid"
	errors "golang.org/x/xerrors"
)

func (h *ActionHandler) ValidateProject(ctx context.Context, project *types.Project) error {
	if project.Name == "" {
		return util.NewErrBadRequest(errors.Errorf("project name required"))
	}
	if !util.ValidateName(project.Name) {
		return util.NewErrBadRequest(errors.Errorf("invalid project name %q", project.Name))
	}
	if project.Parent.ID == "" {
		return util.NewErrBadRequest(errors.Errorf("project parent id required"))
	}
	if project.Parent.Type != types.ConfigTypeProjectGroup {
		return util.NewErrBadRequest(errors.Errorf("invalid project parent type %q", project.Parent.Type))
	}
	if !types.IsValidVisibility(project.Visibility) {
		return util.NewErrBadRequest(errors.Errorf("invalid project visibility"))
	}
	if !types.IsValidRemoteRepositoryConfigType(project.RemoteRepositoryConfigType) {
		return util.NewErrBadRequest(errors.Errorf("invalid project remote repository config type %q", project.RemoteRepositoryConfigType))
	}
	if project.RemoteRepositoryConfigType == types.RemoteRepositoryConfigTypeRemoteSource {
		if project.RemoteSourceID == "" {
			return util.NewErrBadRequest(errors.Errorf("empty remote source id"))
		}
		if project.LinkedAccountID == "" {
			return util.NewErrBadRequest(errors.Errorf("empty linked account id"))
		}
		if project.RepositoryID == "" {
			return util.NewErrBadRequest(errors.Errorf("empty remote repository id"))
		}
		if project.RepositoryPath == "" {
			return util.NewErrBadRequest(errors.Errorf("empty remote repository path"))
		}
	}
	return nil
}

func (h *ActionHandler) GetProject(ctx context.Context, projectRef string) (*types.Project, error) {
	var project *types.Project
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		project, err = h.readDB.GetProject(tx, projectRef)
		return err
	})
	if err != nil {
		return nil, err
	}

	if project == nil {
		return nil, util.NewErrNotExist(errors.Errorf("project %q doesn't exist", projectRef))
	}

	return project, nil
}

func (h *ActionHandler) CreateProject(ctx context.Context, project *types.Project) (*types.Project, error) {
	if err := h.ValidateProject(ctx, project); err != nil {
		return nil, err
	}

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
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

		if project.RemoteRepositoryConfigType == types.RemoteRepositoryConfigTypeRemoteSource {
			// check that the linked account matches the remote source
			user, err := h.readDB.GetUserByLinkedAccount(tx, project.LinkedAccountID)
			if err != nil {
				return errors.Errorf("failed to get user with linked account id %q: %w", project.LinkedAccountID, err)
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
	// generate the Secret and the WebhookSecret
	project.Secret = util.EncodeSha1Hex(uuid.NewV4().String())
	project.WebhookSecret = util.EncodeSha1Hex(uuid.NewV4().String())

	pcj, err := json.Marshal(project)
	if err != nil {
		return nil, errors.Errorf("failed to marshal project: %w", err)
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

type UpdateProjectRequest struct {
	ProjectRef string

	Project *types.Project
}

func (h *ActionHandler) UpdateProject(ctx context.Context, req *UpdateProjectRequest) (*types.Project, error) {
	if err := h.ValidateProject(ctx, req.Project); err != nil {
		return nil, err
	}

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		// check project exists
		p, err := h.readDB.GetProject(tx, req.ProjectRef)
		if err != nil {
			return err
		}
		if p == nil {
			return util.NewErrBadRequest(errors.Errorf("project with ref %q doesn't exist", req.ProjectRef))
		}
		// check that the project.ID matches
		if p.ID != req.Project.ID {
			return util.NewErrBadRequest(errors.Errorf("project with ref %q has a different id", req.ProjectRef))
		}

		// check parent project group exists
		group, err := h.readDB.GetProjectGroup(tx, req.Project.Parent.ID)
		if err != nil {
			return err
		}
		if group == nil {
			return util.NewErrBadRequest(errors.Errorf("project group with id %q doesn't exist", req.Project.Parent.ID))
		}
		req.Project.Parent.ID = group.ID

		groupPath, err := h.readDB.GetProjectGroupPath(tx, group)
		if err != nil {
			return err
		}
		pp := path.Join(groupPath, req.Project.Name)

		if p.Name != req.Project.Name || p.Parent.ID != req.Project.Parent.ID {
			// check duplicate project name
			ap, err := h.readDB.GetProjectByName(tx, req.Project.Parent.ID, req.Project.Name)
			if err != nil {
				return err
			}
			if ap != nil {
				return util.NewErrBadRequest(errors.Errorf("project with name %q, path %q already exists", req.Project.Name, pp))
			}
		}

		// changegroup is the project path. Use "projectpath" prefix as it must
		// cover both projects and projectgroups
		cgNames := []string{util.EncodeSha256Hex("projectpath-" + pp)}

		// add new projectpath
		if p.Parent.ID != req.Project.Parent.ID {
			// get old parent project group
			curGroup, err := h.readDB.GetProjectGroup(tx, p.Parent.ID)
			if err != nil {
				return err
			}
			if curGroup == nil {
				return util.NewErrBadRequest(errors.Errorf("project group with id %q doesn't exist", p.Parent.ID))
			}
			curGroupPath, err := h.readDB.GetProjectGroupPath(tx, curGroup)
			if err != nil {
				return err
			}
			pp := path.Join(curGroupPath, req.Project.Name)

			cgNames = append(cgNames, util.EncodeSha256Hex("projectpath-"+pp))
		}

		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		if req.Project.RemoteRepositoryConfigType == types.RemoteRepositoryConfigTypeRemoteSource {
			// check that the linked account matches the remote source
			user, err := h.readDB.GetUserByLinkedAccount(tx, req.Project.LinkedAccountID)
			if err != nil {
				return errors.Errorf("failed to get user with linked account id %q: %w", req.Project.LinkedAccountID, err)
			}
			if user == nil {
				return util.NewErrBadRequest(errors.Errorf("user for linked account %q doesn't exist", req.Project.LinkedAccountID))
			}
			la, ok := user.LinkedAccounts[req.Project.LinkedAccountID]
			if !ok {
				return util.NewErrBadRequest(errors.Errorf("linked account id %q for user %q doesn't exist", req.Project.LinkedAccountID, user.Name))
			}
			if la.RemoteSourceID != req.Project.RemoteSourceID {
				return util.NewErrBadRequest(errors.Errorf("linked account id %q remote source %q different than project remote source %q", req.Project.LinkedAccountID, la.RemoteSourceID, req.Project.RemoteSourceID))
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	pcj, err := json.Marshal(req.Project)
	if err != nil {
		return nil, errors.Errorf("failed to marshal project: %w", err)
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeProject),
			ID:         req.Project.ID,
			Data:       pcj,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return req.Project, err
}

func (h *ActionHandler) DeleteProject(ctx context.Context, projectRef string) error {
	var project *types.Project

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
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

	// TODO(sgotti) implement childs garbage collection
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
