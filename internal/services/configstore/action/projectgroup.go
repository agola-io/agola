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
	"strings"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/sql"

	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"
)

func (h *ActionHandler) GetProjectGroup(ctx context.Context, projectGroupRef string) (*types.ProjectGroup, error) {
	var projectGroup *types.ProjectGroup
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		projectGroup, err = h.d.GetProjectGroup(tx, projectGroupRef)
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
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		projectGroup, err := h.d.GetProjectGroup(tx, projectGroupRef)
		if err != nil {
			return errors.WithStack(err)
		}

		if projectGroup == nil {
			return util.NewAPIError(util.ErrNotExist, errors.Errorf("project group %q doesn't exist", projectGroupRef))
		}

		projectGroups, err = h.d.GetProjectGroupSubgroups(tx, projectGroup.ID)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return projectGroups, nil
}

func (h *ActionHandler) GetProjectGroupProjects(ctx context.Context, projectGroupRef string) ([]*types.Project, error) {
	var projects []*types.Project
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		projectGroup, err := h.d.GetProjectGroup(tx, projectGroupRef)
		if err != nil {
			return errors.WithStack(err)
		}

		if projectGroup == nil {
			return util.NewAPIError(util.ErrNotExist, errors.Errorf("project group %q doesn't exist", projectGroupRef))
		}

		projects, err = h.d.GetProjectGroupProjects(tx, projectGroup.ID)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return projects, nil
}

func (h *ActionHandler) ValidateProjectGroupReq(ctx context.Context, req *CreateUpdateProjectGroupRequest) error {
	if req.Parent.Kind != types.ObjectKindProjectGroup &&
		req.Parent.Kind != types.ObjectKindOrg &&
		req.Parent.Kind != types.ObjectKindUser {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid project group parent kind %q", req.Parent.Kind))
	}
	if req.Parent.ID == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group parent id required"))
	}

	// if the project group is a root project group the name must be empty
	if req.Parent.Kind == types.ObjectKindOrg ||
		req.Parent.Kind == types.ObjectKindUser {
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

	// We cannot create a root project group for org/user since it's created on user/org creation
	if req.Parent.Kind != types.ObjectKindProjectGroup {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("wrong project group parent kind %q", req.Parent.Kind))
	}

	var projectGroup *types.ProjectGroup
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		parentProjectGroup, err := h.d.GetProjectGroup(tx, req.Parent.ID)
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

		groupPath, err := h.d.GetProjectGroupPath(tx, parentProjectGroup)
		if err != nil {
			return errors.WithStack(err)
		}
		pp := path.Join(groupPath, req.Name)

		// check duplicate project group name
		tpg, err := h.d.GetProjectGroupByName(tx, req.Parent.ID, req.Name)
		if err != nil {
			return errors.WithStack(err)
		}
		if tpg != nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group with name %q, path %q already exists", req.Name, pp))
		}

		projectGroup = types.NewProjectGroup()
		projectGroup.Name = req.Name
		projectGroup.Parent = req.Parent
		projectGroup.Visibility = req.Visibility

		if err := h.d.InsertProjectGroup(tx, projectGroup); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return projectGroup, errors.WithStack(err)
}

func (h *ActionHandler) UpdateProjectGroup(ctx context.Context, curProjectGroupRef string, req *CreateUpdateProjectGroupRequest) (*types.ProjectGroup, error) {
	if err := h.ValidateProjectGroupReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var projectGroup *types.ProjectGroup
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		// check project exists
		projectGroup, err = h.d.GetProjectGroup(tx, curProjectGroupRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if projectGroup == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group with ref %q doesn't exist", curProjectGroupRef))
		}

		if projectGroup.Parent.Kind != req.Parent.Kind {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("changing project group parent kind isn't supported"))
		}

		switch projectGroup.Parent.Kind {
		case types.ObjectKindOrg:
			fallthrough
		case types.ObjectKindUser:
			// Cannot update root project group parent
			if projectGroup.Parent.Kind != req.Parent.Kind || projectGroup.Parent.ID != req.Parent.ID {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot change root project group parent kind or id"))
			}
			// if the project group is a root project group force the name to be empty
			req.Name = ""

		case types.ObjectKindProjectGroup:
			// check parent exists
			group, err := h.d.GetProjectGroup(tx, req.Parent.ID)
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

		curPGParentPath, err := h.d.GetPath(tx, projectGroup.Parent.Kind, projectGroup.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		curPGP := path.Join(curPGParentPath, projectGroup.Name)

		pgParentPath, err := h.d.GetPath(tx, req.Parent.Kind, req.Parent.ID)
		if err != nil {
			return errors.WithStack(err)
		}
		pgp := path.Join(pgParentPath, req.Name)

		if projectGroup.Name != req.Name || projectGroup.Parent.ID != req.Parent.ID {
			// check duplicate project group name
			ap, err := h.d.GetProjectGroupByName(tx, req.Parent.ID, req.Name)
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

		// update current projectGroup
		projectGroup.Name = req.Name
		projectGroup.Parent = req.Parent
		projectGroup.Visibility = req.Visibility

		if err := h.d.UpdateProjectGroup(tx, projectGroup); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return projectGroup, errors.WithStack(err)
}

func (h *ActionHandler) DeleteProjectGroup(ctx context.Context, projectGroupRef string) error {
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		// check project group existance
		projectGroup, err := h.d.GetProjectGroup(tx, projectGroupRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if projectGroup == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group %q doesn't exist", projectGroupRef))
		}

		// cannot delete root project group
		if projectGroup.Parent.Kind == types.ObjectKindOrg ||
			projectGroup.Parent.Kind == types.ObjectKindUser {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot delete root project group"))
		}

		// TODO(sgotti) implement childs garbage collection
		if err := h.d.DeleteProjectGroup(tx, projectGroup.ID); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(err)
}
