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
	"agola.io/agola/internal/errors"

	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	"github.com/gofrs/uuid"
)

func (h *ActionHandler) ValidateProjectReq(ctx context.Context, req *CreateUpdateProjectRequest) error {
	if req.Name == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project name required"))
	}
	if !util.ValidateName(req.Name) {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid project name %q", req.Name))
	}
	if req.Parent.ID == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project parent id required"))
	}
	if req.Parent.Type != types.ConfigTypeProjectGroup {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid project parent type %q", req.Parent.Type))
	}
	if !types.IsValidVisibility(req.Visibility) {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid project visibility"))
	}
	if !types.IsValidRemoteRepositoryConfigType(req.RemoteRepositoryConfigType) {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid project remote repository config type %q", req.RemoteRepositoryConfigType))
	}
	if req.RemoteRepositoryConfigType == types.RemoteRepositoryConfigTypeRemoteSource {
		if req.RemoteSourceID == "" {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("empty remote source id"))
		}
		if req.LinkedAccountID == "" {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("empty linked account id"))
		}
		if req.RepositoryID == "" {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("empty remote repository id"))
		}
		if req.RepositoryPath == "" {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("empty remote repository path"))
		}
	}
	return nil
}

func (h *ActionHandler) GetProject(ctx context.Context, projectRef string) (*types.Project, error) {
	var project *types.Project
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		project, err = h.readDB.GetProject(tx, projectRef)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if project == nil {
		return nil, util.NewAPIError(util.ErrNotExist, errors.Errorf("project %q doesn't exist", projectRef))
	}

	return project, nil
}

type CreateUpdateProjectRequest struct {
	Name                       string
	Parent                     types.Parent
	Visibility                 types.Visibility
	RemoteRepositoryConfigType types.RemoteRepositoryConfigType
	RemoteSourceID             string
	LinkedAccountID            string
	RepositoryID               string
	RepositoryPath             string
	SSHPrivateKey              string
	SkipSSHHostKeyCheck        bool
	PassVarsToForkedPR         bool
}

func (h *ActionHandler) CreateProject(ctx context.Context, req *CreateUpdateProjectRequest) (*types.Project, error) {
	if err := h.ValidateProjectReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		group, err := h.readDB.GetProjectGroup(tx, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		if group == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group with id %q doesn't exist", req.Parent.ID))
		}
		req.Parent.ID = group.ID

		groupPath, err := h.readDB.GetProjectGroupPath(tx, group)
		if err != nil {
			return errors.WithStack(err)
		}
		pp := path.Join(groupPath, req.Name)

		// changegroup is the project path. Use "projectpath" prefix as it must
		// cover both projects and projectgroups
		cgNames := []string{util.EncodeSha256Hex("projectpath-" + pp)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return errors.WithStack(err)
		}

		// check duplicate project name
		p, err := h.readDB.GetProjectByName(tx, req.Parent.ID, req.Name)
		if err != nil {
			return errors.WithStack(err)
		}
		if p != nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with name %q, path %q already exists", p.Name, pp))
		}

		if req.RemoteRepositoryConfigType == types.RemoteRepositoryConfigTypeRemoteSource {
			// check that the linked account matches the remote source
			user, err := h.readDB.GetUserByLinkedAccount(tx, req.LinkedAccountID)
			if err != nil {
				return errors.Wrapf(err, "failed to get user with linked account id %q", req.LinkedAccountID)
			}
			if user == nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("user for linked account %q doesn't exist", req.LinkedAccountID))
			}
			la, ok := user.LinkedAccounts[req.LinkedAccountID]
			if !ok {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("linked account id %q for user %q doesn't exist", req.LinkedAccountID, user.Name))
			}
			if la.RemoteSourceID != req.RemoteSourceID {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("linked account id %q remote source %q different than project remote source %q", req.LinkedAccountID, la.RemoteSourceID, req.RemoteSourceID))
			}
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	project := &types.Project{}
	project.ID = uuid.Must(uuid.NewV4()).String()
	project.Name = req.Name
	project.Parent = req.Parent
	project.Visibility = req.Visibility
	project.RemoteRepositoryConfigType = req.RemoteRepositoryConfigType
	project.RemoteSourceID = req.RemoteSourceID
	project.LinkedAccountID = req.LinkedAccountID
	project.RepositoryID = req.RepositoryID
	project.RepositoryPath = req.RepositoryPath
	project.SSHPrivateKey = req.SSHPrivateKey
	project.SkipSSHHostKeyCheck = req.SkipSSHHostKeyCheck
	project.PassVarsToForkedPR = req.PassVarsToForkedPR

	// generate the Secret and the WebhookSecret
	// TODO(sgotti) move this to the gateway?
	project.Secret = util.EncodeSha1Hex(uuid.Must(uuid.NewV4()).String())
	project.WebhookSecret = util.EncodeSha1Hex(uuid.Must(uuid.NewV4()).String())

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
	return project, errors.WithStack(err)
}

func (h *ActionHandler) UpdateProject(ctx context.Context, curProjectRef string, req *CreateUpdateProjectRequest) (*types.Project, error) {
	if err := h.ValidateProjectReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var cgt *datamanager.ChangeGroupsUpdateToken

	var project *types.Project
	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		// check project exists
		project, err = h.readDB.GetProject(tx, curProjectRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if project == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with ref %q doesn't exist", curProjectRef))
		}

		// check parent project group exists
		group, err := h.readDB.GetProjectGroup(tx, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		if group == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group with id %q doesn't exist", req.Parent.ID))
		}
		req.Parent.ID = group.ID

		groupPath, err := h.readDB.GetProjectGroupPath(tx, group)
		if err != nil {
			return errors.WithStack(err)
		}
		pp := path.Join(groupPath, req.Name)

		if project.Name != req.Name || project.Parent.ID != req.Parent.ID {
			// check duplicate project name
			ap, err := h.readDB.GetProjectByName(tx, req.Parent.ID, req.Name)
			if err != nil {
				return errors.WithStack(err)
			}
			if ap != nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with name %q, path %q already exists", req.Name, pp))
			}
		}

		// changegroup is the project path. Use "projectpath" prefix as it must
		// cover both projects and projectgroups
		cgNames := []string{util.EncodeSha256Hex("projectpath-" + pp)}

		// add new projectpath
		if project.Parent.ID != req.Parent.ID {
			// get old parent project group
			curGroup, err := h.readDB.GetProjectGroup(tx, project.Parent.ID)
			if err != nil {
				return errors.WithStack(err)
			}
			if curGroup == nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group with id %q doesn't exist", project.Parent.ID))
			}
			curGroupPath, err := h.readDB.GetProjectGroupPath(tx, curGroup)
			if err != nil {
				return errors.WithStack(err)
			}
			pp := path.Join(curGroupPath, req.Name)

			cgNames = append(cgNames, util.EncodeSha256Hex("projectpath-"+pp))
		}

		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return errors.WithStack(err)
		}

		if req.RemoteRepositoryConfigType == types.RemoteRepositoryConfigTypeRemoteSource {
			// check that the linked account matches the remote source
			user, err := h.readDB.GetUserByLinkedAccount(tx, req.LinkedAccountID)
			if err != nil {
				return errors.Wrapf(err, "failed to get user with linked account id %q", req.LinkedAccountID)
			}
			if user == nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("user for linked account %q doesn't exist", req.LinkedAccountID))
			}
			la, ok := user.LinkedAccounts[req.LinkedAccountID]
			if !ok {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("linked account id %q for user %q doesn't exist", req.LinkedAccountID, user.Name))
			}
			if la.RemoteSourceID != req.RemoteSourceID {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("linked account id %q remote source %q different than project remote source %q", req.LinkedAccountID, la.RemoteSourceID, req.RemoteSourceID))
			}
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// TODO(sgotti) Secret and WebhookSecret are not updated
	project.Name = req.Name
	project.Parent = req.Parent
	project.Visibility = req.Visibility
	project.RemoteRepositoryConfigType = req.RemoteRepositoryConfigType
	project.RemoteSourceID = req.RemoteSourceID
	project.LinkedAccountID = req.LinkedAccountID
	project.RepositoryID = req.RepositoryID
	project.RepositoryPath = req.RepositoryPath
	project.SSHPrivateKey = req.SSHPrivateKey
	project.SkipSSHHostKeyCheck = req.SkipSSHHostKeyCheck
	project.PassVarsToForkedPR = req.PassVarsToForkedPR

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
	return project, errors.WithStack(err)
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
			return errors.WithStack(err)
		}
		if project == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project %q doesn't exist", projectRef))
		}

		// changegroup is the project id.
		cgNames := []string{util.EncodeSha256Hex(project.ID)}
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
			DataType:   string(types.ConfigTypeProject),
			ID:         project.ID,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return errors.WithStack(err)
}
