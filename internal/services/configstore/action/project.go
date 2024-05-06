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

	"github.com/gofrs/uuid"
	"github.com/sorintlab/errors"

	serrors "agola.io/agola/internal/services/errors"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"
)

type ProjectDynamicData struct {
	OwnerType        types.ObjectKind
	OwnerID          string
	Path             string
	ParentPath       string
	GlobalVisibility types.Visibility
}

func (h *ActionHandler) projectDynamicData(tx *sql.Tx, project *types.Project) (*ProjectDynamicData, error) {
	var projectDynamicData *ProjectDynamicData

	pp, err := h.GetPath(tx, project.Parent.Kind, project.Parent.ID)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	ownerType, ownerID, err := h.GetProjectOwnerID(tx, project)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// calculate global visibility
	visibility, err := h.getGlobalVisibility(tx, project.Visibility, &project.Parent)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	projectDynamicData = &ProjectDynamicData{
		OwnerType:        ownerType,
		OwnerID:          ownerID,
		Path:             path.Join(pp, project.Name),
		ParentPath:       pp,
		GlobalVisibility: visibility,
	}

	return projectDynamicData, nil
}

func (h *ActionHandler) ValidateProjectReq(ctx context.Context, req *CreateUpdateProjectRequest) error {
	if req.Name == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("project name required"), serrors.InvalidProjectName())
	}
	if !util.ValidateName(req.Name) {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("invalid project name %q", req.Name), serrors.InvalidProjectName())
	}
	if req.Parent.ID == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("project parent id required"))
	}
	if req.Parent.Kind != types.ObjectKindProjectGroup {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("invalid project parent kind %q", req.Parent.Kind))
	}
	if !types.IsValidVisibility(req.Visibility) {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("invalid project visibility"))
	}
	if !types.IsValidRemoteRepositoryConfigType(req.RemoteRepositoryConfigType) {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("invalid project remote repository config type %q", req.RemoteRepositoryConfigType))
	}
	if req.RemoteRepositoryConfigType == types.RemoteRepositoryConfigTypeRemoteSource {
		if req.RemoteSourceID == "" {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("empty remote source id"))
		}
		if req.LinkedAccountID == "" {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("empty linked account id"))
		}
		if req.RepositoryID == "" {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("empty remote repository id"))
		}
		if req.RepositoryPath == "" {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("empty remote repository path"))
		}
	}
	return nil
}

type GetProjectResponse struct {
	Project            *types.Project
	ProjectDynamicData *ProjectDynamicData
}

func (h *ActionHandler) GetProject(ctx context.Context, projectRef string) (*GetProjectResponse, error) {
	var project *types.Project
	var projectDynamicData *ProjectDynamicData
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		project, err = h.GetProjectByRef(tx, projectRef)

		if err != nil {
			return errors.WithStack(err)
		}

		if project == nil {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("project %q doesn't exist", projectRef), serrors.ProjectDoesNotExist())
		}

		projectDynamicData, err = h.projectDynamicData(tx, project)

		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &GetProjectResponse{
		Project:            project,
		ProjectDynamicData: projectDynamicData,
	}, nil
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
	DefaultBranch              string
	// MembersCanPerformRunActions defines if project organization members can restart/stop/cancel a project run
	MembersCanPerformRunActions bool
}

func (h *ActionHandler) CreateProject(ctx context.Context, req *CreateUpdateProjectRequest) (*GetProjectResponse, error) {
	if err := h.ValidateProjectReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var project *types.Project
	var projectDynamicData *ProjectDynamicData
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		group, err := h.GetProjectGroupByRef(tx, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		if group == nil {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("parent project group with id %q doesn't exist", req.Parent.ID), serrors.ParentProjectGroupDoesNotExist())
		}
		req.Parent.ID = group.ID

		ownerType, _, err := h.GetProjectGroupOwnerID(tx, group)
		if err != nil {
			return errors.WithStack(err)
		}
		if ownerType == types.ObjectKindUser && req.MembersCanPerformRunActions {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("cannot set MembersCanPerformRunActions on an user project."), serrors.CannotSetMembersCanPerformRunActionsOnUserProject())
		}

		groupPath, err := h.GetProjectGroupPath(tx, group)
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
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("project with name %q, path %q already exists", p.Name, pp), serrors.ProjectAlreadyExists())
		}

		if req.RemoteRepositoryConfigType == types.RemoteRepositoryConfigTypeRemoteSource {
			la, err := h.d.GetLinkedAccount(tx, req.LinkedAccountID)
			if err != nil {
				return errors.Wrapf(err, "failed to get user with linked account id %q", req.LinkedAccountID)
			}
			if la == nil {
				return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("linked account id %q doesn't exist", req.LinkedAccountID))
			}

			user, err := h.d.GetUserByID(tx, la.UserID)
			if err != nil {
				return errors.Wrapf(err, "failed to get user with linked account id %q", req.LinkedAccountID)
			}
			if user == nil {
				return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("user for linked account %q doesn't exist", req.LinkedAccountID))
			}

			// check that the linked account matches the remote source
			if la.RemoteSourceID != req.RemoteSourceID {
				return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("linked account id %q remote source %q different than project remote source %q", req.LinkedAccountID, la.RemoteSourceID, req.RemoteSourceID))
			}
		}

		project = types.NewProject(tx)
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
		project.DefaultBranch = req.DefaultBranch
		project.MembersCanPerformRunActions = req.MembersCanPerformRunActions

		// generate the Secret and the WebhookSecret
		// TODO(sgotti) move this to the gateway?
		project.Secret = util.EncodeSha1Hex(uuid.Must(uuid.NewV4()).String())
		project.WebhookSecret = util.EncodeSha1Hex(uuid.Must(uuid.NewV4()).String())

		if err := h.d.InsertProject(tx, project); err != nil {
			return errors.WithStack(err)
		}

		projectDynamicData, err = h.projectDynamicData(tx, project)

		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &GetProjectResponse{
		Project:            project,
		ProjectDynamicData: projectDynamicData,
	}, nil
}

func (h *ActionHandler) UpdateProject(ctx context.Context, curProjectRef string, req *CreateUpdateProjectRequest) (*GetProjectResponse, error) {
	if err := h.ValidateProjectReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var project *types.Project
	var projectDynamicData *ProjectDynamicData
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		// check project exists
		project, err = h.GetProjectByRef(tx, curProjectRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if project == nil {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("project with ref %q doesn't exist", curProjectRef), serrors.ProjectDoesNotExist())
		}

		// check parent project group exists
		group, err := h.GetProjectGroupByRef(tx, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		if group == nil {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("parent project group with id %q doesn't exist", req.Parent.ID), serrors.ParentProjectGroupDoesNotExist())
		}
		req.Parent.ID = group.ID

		ownerType, _, err := h.GetProjectGroupOwnerID(tx, group)
		if err != nil {
			return errors.WithStack(err)
		}
		if ownerType == types.ObjectKindUser && req.MembersCanPerformRunActions {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("cannot set MembersCanPerformRunActions on an user project."), serrors.CannotSetMembersCanPerformRunActionsOnUserProject())
		}

		groupPath, err := h.GetProjectGroupPath(tx, group)
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
				return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("project with name %q, path %q already exists", req.Name, pp), serrors.ProjectAlreadyExists())
			}
		}

		if project.Parent.ID != req.Parent.ID {
			// get old parent project group
			curGroup, err := h.GetProjectGroupByRef(tx, project.Parent.ID)
			if err != nil {
				return errors.WithStack(err)
			}
			if curGroup == nil {
				return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("parent project group with id %q doesn't exist", project.Parent.ID), serrors.ParentProjectGroupDoesNotExist())
			}
		}

		if req.RemoteRepositoryConfigType == types.RemoteRepositoryConfigTypeRemoteSource {
			la, err := h.d.GetLinkedAccount(tx, req.LinkedAccountID)
			if err != nil {
				return errors.Wrapf(err, "failed to get user with linked account id %q", req.LinkedAccountID)
			}
			if la == nil {
				return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("linked account id %q doesn't exist", req.LinkedAccountID))
			}

			user, err := h.d.GetUserByID(tx, la.UserID)
			if err != nil {
				return errors.Wrapf(err, "failed to get user with linked account id %q", req.LinkedAccountID)
			}
			if user == nil {
				return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("user for linked account %q doesn't exist", req.LinkedAccountID))
			}

			// check that the linked account matches the remote source
			if la.RemoteSourceID != req.RemoteSourceID {
				return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("linked account id %q remote source %q different than project remote source %q", req.LinkedAccountID, la.RemoteSourceID, req.RemoteSourceID))
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
		project.DefaultBranch = req.DefaultBranch
		project.MembersCanPerformRunActions = req.MembersCanPerformRunActions

		if err := h.d.UpdateProject(tx, project); err != nil {
			return errors.WithStack(err)
		}

		projectDynamicData, err = h.projectDynamicData(tx, project)

		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &GetProjectResponse{
		Project:            project,
		ProjectDynamicData: projectDynamicData,
	}, nil
}

func (h *ActionHandler) DeleteProject(ctx context.Context, projectRef string) error {
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		// check project existance
		project, err := h.GetProjectByRef(tx, projectRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if project == nil {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("project %q doesn't exist", projectRef), serrors.ProjectDoesNotExist())
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
