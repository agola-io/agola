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

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/sql"

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
	if req.Parent.Kind != types.ObjectKindProjectGroup {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid project parent kind %q", req.Parent.Kind))
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
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		project, err = h.d.GetProject(tx, projectRef)
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

	var project *types.Project
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		group, err := h.d.GetProjectGroup(tx, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		if group == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group with id %q doesn't exist", req.Parent.ID))
		}
		req.Parent.ID = group.ID

		groupPath, err := h.d.GetProjectGroupPath(tx, group)
		if err != nil {
			return errors.WithStack(err)
		}
		pp := path.Join(groupPath, req.Name)

		// check duplicate project name
		p, err := h.d.GetProjectByName(tx, req.Parent.ID, req.Name)
		if err != nil {
			return errors.WithStack(err)
		}
		if p != nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with name %q, path %q already exists", p.Name, pp))
		}

		if req.RemoteRepositoryConfigType == types.RemoteRepositoryConfigTypeRemoteSource {
			la, err := h.d.GetLinkedAccount(tx, req.LinkedAccountID)
			if err != nil {
				return errors.Wrapf(err, "failed to get user with linked account id %q", req.LinkedAccountID)
			}
			if la == nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("linked account id %q doesn't exist", req.LinkedAccountID))
			}

			user, err := h.d.GetUserByID(tx, la.UserID)
			if err != nil {
				return errors.Wrapf(err, "failed to get user with linked account id %q", req.LinkedAccountID)
			}
			if user == nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("user for linked account %q doesn't exist", req.LinkedAccountID))
			}

			// check that the linked account matches the remote source
			if la.RemoteSourceID != req.RemoteSourceID {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("linked account id %q remote source %q different than project remote source %q", req.LinkedAccountID, la.RemoteSourceID, req.RemoteSourceID))
			}
		}

		project = types.NewProject()
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

		if err := h.d.InsertProject(tx, project); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return project, errors.WithStack(err)
}

func (h *ActionHandler) UpdateProject(ctx context.Context, curProjectRef string, req *CreateUpdateProjectRequest) (*types.Project, error) {
	if err := h.ValidateProjectReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var project *types.Project
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		// check project exists
		project, err = h.d.GetProject(tx, curProjectRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if project == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with ref %q doesn't exist", curProjectRef))
		}

		// check parent project group exists
		group, err := h.d.GetProjectGroup(tx, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		if group == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group with id %q doesn't exist", req.Parent.ID))
		}
		req.Parent.ID = group.ID

		groupPath, err := h.d.GetProjectGroupPath(tx, group)
		if err != nil {
			return errors.WithStack(err)
		}
		pp := path.Join(groupPath, req.Name)

		if project.Name != req.Name || project.Parent.ID != req.Parent.ID {
			// check duplicate project name
			ap, err := h.d.GetProjectByName(tx, req.Parent.ID, req.Name)
			if err != nil {
				return errors.WithStack(err)
			}
			if ap != nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with name %q, path %q already exists", req.Name, pp))
			}
		}

		if project.Parent.ID != req.Parent.ID {
			// get old parent project group
			curGroup, err := h.d.GetProjectGroup(tx, project.Parent.ID)
			if err != nil {
				return errors.WithStack(err)
			}
			if curGroup == nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group with id %q doesn't exist", project.Parent.ID))
			}
		}

		if req.RemoteRepositoryConfigType == types.RemoteRepositoryConfigTypeRemoteSource {
			la, err := h.d.GetLinkedAccount(tx, req.LinkedAccountID)
			if err != nil {
				return errors.Wrapf(err, "failed to get user with linked account id %q", req.LinkedAccountID)
			}
			if la == nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("linked account id %q doesn't exist", req.LinkedAccountID))
			}

			user, err := h.d.GetUserByID(tx, la.UserID)
			if err != nil {
				return errors.Wrapf(err, "failed to get user with linked account id %q", req.LinkedAccountID)
			}
			if user == nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("user for linked account %q doesn't exist", req.LinkedAccountID))
			}

			// check that the linked account matches the remote source
			if la.RemoteSourceID != req.RemoteSourceID {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("linked account id %q remote source %q different than project remote source %q", req.LinkedAccountID, la.RemoteSourceID, req.RemoteSourceID))
			}
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

		if err := h.d.UpdateProject(tx, project); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return project, errors.WithStack(err)
}

func (h *ActionHandler) DeleteProject(ctx context.Context, projectRef string) error {
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		// check project existance
		project, err := h.d.GetProject(tx, projectRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if project == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project %q doesn't exist", projectRef))
		}

		// TODO(sgotti) implement childs garbage collection
		if err := h.d.DeleteProject(tx, project.ID); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(err)
}
