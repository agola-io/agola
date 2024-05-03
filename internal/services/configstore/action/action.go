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
	"path"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/configstore/common"
	"agola.io/agola/internal/services/configstore/db"
	serrors "agola.io/agola/internal/services/errors"
	"agola.io/agola/internal/sqlg/lock"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"
)

type ActionHandler struct {
	log                  zerolog.Logger
	d                    *db.DB
	lf                   lock.LockFactory
	maintenanceMode      bool
	maintenanceModeMutex sync.Mutex
}

func NewActionHandler(log zerolog.Logger, d *db.DB, lf lock.LockFactory) *ActionHandler {
	return &ActionHandler{
		log:             log,
		d:               d,
		lf:              lf,
		maintenanceMode: false,
	}
}

func (h *ActionHandler) GetProjectGroupByPath(tx *sql.Tx, projectGroupPath string) (*types.ProjectGroup, error) {
	parts := strings.Split(projectGroupPath, "/")
	if len(parts) < 2 {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("wrong project group path: %q", projectGroupPath), serrors.InvalidPath())
	}
	var parentID string
	switch parts[0] {
	case "org":
		org, err := h.d.GetOrgByName(tx, parts[1])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get organization %q", parts[1])
		}
		if org == nil {
			return nil, util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("organization with name %q doesn't exist", parts[1]), serrors.OrganizationDoesNotExist())
		}
		parentID = org.ID
	case "user":
		user, err := h.d.GetUserByName(tx, parts[1])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get user %q", parts[1])
		}
		if user == nil {
			return nil, util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("user with name %q doesn't exist", parts[1]), serrors.UserDoesNotExist())
		}
		parentID = user.ID
	default:
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("wrong project group path: %q", projectGroupPath), serrors.InvalidPath())
	}

	var projectGroup *types.ProjectGroup
	// add root project group (empty name)
	for _, projectGroupName := range append([]string{""}, parts[2:]...) {
		var err error
		projectGroup, err = h.d.GetProjectGroupByName(tx, parentID, projectGroupName)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get project group %q", projectGroupName)
		}
		if projectGroup == nil {
			return nil, nil
		}
		parentID = projectGroup.ID
	}

	return projectGroup, nil
}

func (h *ActionHandler) GetProjectByPath(tx *sql.Tx, projectPath string) (*types.Project, error) {
	if len(strings.Split(projectPath, "/")) < 3 {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("wrong project path: %q", projectPath), serrors.InvalidPath())
	}

	projectGroupPath := path.Dir(projectPath)
	projectName := path.Base(projectPath)
	projectGroup, err := h.GetProjectGroupByPath(tx, projectGroupPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get project group %q", projectGroupPath)
	}
	if projectGroup == nil {
		return nil, nil
	}

	project, err := h.d.GetProjectByName(tx, projectGroup.ID, projectName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get project group %q", projectName)
	}

	return project, nil
}

func (h *ActionHandler) GetProjectGroupPath(tx *sql.Tx, group *types.ProjectGroup) (string, error) {
	var p string

	groups, err := h.GetProjectGroupHierarchy(tx, group)
	if err != nil {
		return "", errors.WithStack(err)
	}

	rootGroupType := groups[0].ParentKind
	rootGroupID := groups[0].ParentID
	switch rootGroupType {
	case types.ObjectKindOrg:
		fallthrough
	case types.ObjectKindUser:
		var err error
		p, err = h.GetPath(tx, rootGroupType, rootGroupID)
		if err != nil {
			return "", errors.WithStack(err)
		}
	default:
		return "", errors.Errorf("invalid root group type %q", rootGroupType)
	}

	for _, group := range groups {
		p = path.Join(p, group.Name)
	}

	return p, nil
}

func (h *ActionHandler) GetProjectPath(tx *sql.Tx, project *types.Project) (string, error) {
	pgroup, err := h.GetProjectGroupByRef(tx, project.Parent.ID)
	if err != nil {
		return "", errors.WithStack(err)
	}
	if pgroup == nil {
		return "", util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("parent project group %q for project %q doesn't exist", project.Parent.ID, project.ID), serrors.ParentProjectGroupDoesNotExist())
	}
	p, err := h.GetProjectGroupPath(tx, pgroup)
	if err != nil {
		return "", errors.WithStack(err)
	}

	p = path.Join(p, project.Name)

	return p, nil
}

func (h *ActionHandler) GetProjectGroupByRef(tx *sql.Tx, projectGroupRef string) (*types.ProjectGroup, error) {
	groupRef, err := common.ParsePathRef(projectGroupRef)
	if err != nil {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("wrong project group ref: %q", projectGroupRef), serrors.InvalidRef())
	}

	var group *types.ProjectGroup
	switch groupRef {
	case common.RefTypeID:
		group, err = h.d.GetProjectGroupByID(tx, projectGroupRef)
	case common.RefTypePath:
		group, err = h.GetProjectGroupByPath(tx, projectGroupRef)
	}
	return group, errors.WithStack(err)
}

func (h *ActionHandler) GetProjectByRef(tx *sql.Tx, projectRef string) (*types.Project, error) {
	projectRefType, err := common.ParsePathRef(projectRef)
	if err != nil {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("wrong project ref: %q", projectRef), serrors.InvalidRef())
	}

	var project *types.Project
	switch projectRefType {
	case common.RefTypeID:
		project, err = h.d.GetProjectByID(tx, projectRef)
	case common.RefTypePath:
		project, err = h.GetProjectByPath(tx, projectRef)
	}
	return project, errors.WithStack(err)
}

func (h *ActionHandler) GetOrgByRef(tx *sql.Tx, orgRef string) (*types.Organization, error) {
	refType, err := common.ParseNameRef(orgRef)
	if err != nil {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("wrong organization ref: %q", orgRef), serrors.InvalidRef())
	}

	var org *types.Organization
	switch refType {
	case common.RefTypeID:
		org, err = h.d.GetOrgByID(tx, orgRef)
	case common.RefTypeName:
		org, err = h.d.GetOrgByName(tx, orgRef)
	}
	return org, errors.WithStack(err)
}

func (h *ActionHandler) GetUserByRef(tx *sql.Tx, userRef string) (*types.User, error) {
	refType, err := common.ParseNameRef(userRef)
	if err != nil {
		return nil, util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("wrong user ref: %q", userRef), serrors.InvalidRef())
	}

	var user *types.User
	switch refType {
	case common.RefTypeID:
		user, err = h.d.GetUserByID(tx, userRef)
	case common.RefTypeName:
		user, err = h.d.GetUserByName(tx, userRef)
	}
	return user, errors.WithStack(err)
}

func (h *ActionHandler) GetPath(tx *sql.Tx, objectKind types.ObjectKind, id string) (string, error) {
	var p string
	switch objectKind {
	case types.ObjectKindProjectGroup:
		projectGroup, err := h.GetProjectGroupByRef(tx, id)
		if err != nil {
			return "", errors.WithStack(err)
		}
		if projectGroup == nil {
			return "", util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("projectgroup with id %q doesn't exist", id), serrors.ProjectGroupDoesNotExist())
		}
		p, err = h.GetProjectGroupPath(tx, projectGroup)
		if err != nil {
			return "", errors.WithStack(err)
		}
	case types.ObjectKindProject:
		project, err := h.GetProjectByRef(tx, id)
		if err != nil {
			return "", errors.WithStack(err)
		}
		if project == nil {
			return "", util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("project with id %q doesn't exist", id), serrors.ProjectDoesNotExist())
		}
		p, err = h.GetProjectPath(tx, project)
		if err != nil {
			return "", errors.WithStack(err)
		}
	case types.ObjectKindOrg:
		org, err := h.GetOrgByRef(tx, id)
		if err != nil {
			return "", errors.Wrapf(err, "failed to get organization %q", id)
		}
		if org == nil {
			return "", util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("organization with id %q doesn't exist", id), serrors.OrganizationDoesNotExist())
		}
		p = path.Join("org", org.Name)
	case types.ObjectKindUser:
		user, err := h.GetUserByRef(tx, id)
		if err != nil {
			return "", errors.Wrapf(err, "failed to get user %q", id)
		}
		if user == nil {
			return "", util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("user with id %q doesn't exist", id), serrors.UserDoesNotExist())
		}
		p = path.Join("user", user.Name)
	default:
		return "", errors.Errorf("config type %q doesn't provide a path", objectKind)
	}

	return p, nil
}

type hierarchyElement struct {
	ID         string
	Name       string
	Kind       types.ObjectKind
	ParentKind types.ObjectKind
	ParentID   string
}

func (h *ActionHandler) GetProjectGroupHierarchy(tx *sql.Tx, projectGroup *types.ProjectGroup) ([]*hierarchyElement, error) {
	projectGroupID := projectGroup.Parent.ID
	elements := []*hierarchyElement{
		{
			ID:         projectGroup.ID,
			Name:       projectGroup.Name,
			Kind:       types.ObjectKindProjectGroup,
			ParentKind: projectGroup.Parent.Kind,
			ParentID:   projectGroup.Parent.ID,
		},
	}

	for projectGroup.Parent.Kind == types.ObjectKindProjectGroup {
		var err error
		projectGroup, err = h.GetProjectGroupByRef(tx, projectGroupID)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get project group %q", projectGroupID)
		}
		if projectGroup == nil {
			return nil, util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("project group %q doesn't exist", projectGroupID), serrors.ProjectGroupDoesNotExist())
		}
		elements = append([]*hierarchyElement{
			{
				ID:         projectGroup.ID,
				Name:       projectGroup.Name,
				Kind:       types.ObjectKindProjectGroup,
				ParentKind: projectGroup.Parent.Kind,
				ParentID:   projectGroup.Parent.ID,
			},
		}, elements...)
		projectGroupID = projectGroup.Parent.ID
	}

	return elements, nil
}

func (h *ActionHandler) GetProjectGroupOwnerID(tx *sql.Tx, group *types.ProjectGroup) (types.ObjectKind, string, error) {
	groups, err := h.GetProjectGroupHierarchy(tx, group)
	if err != nil {
		return "", "", errors.WithStack(err)
	}

	rootGroupType := groups[0].ParentKind
	rootGroupID := groups[0].ParentID
	return rootGroupType, rootGroupID, nil
}

func (h *ActionHandler) GetProjectOwnerID(tx *sql.Tx, project *types.Project) (types.ObjectKind, string, error) {
	pgroup, err := h.GetProjectGroupByRef(tx, project.Parent.ID)
	if err != nil {
		return "", "", errors.WithStack(err)
	}
	if pgroup == nil {
		return "", "", util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("parent project group %q for project %q doesn't exist", project.Parent.ID, project.ID), serrors.ParentProjectGroupDoesNotExist())
	}
	return h.GetProjectGroupOwnerID(tx, pgroup)
}

func (h *ActionHandler) ResolveObjectID(tx *sql.Tx, objectKind types.ObjectKind, ref string) (string, error) {
	switch objectKind {
	case types.ObjectKindProjectGroup:
		group, err := h.GetProjectGroupByRef(tx, ref)
		if err != nil {
			return "", errors.WithStack(err)
		}
		if group == nil {
			return "", util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("project group with ref %q doesn't exists", ref), serrors.ProjectGroupDoesNotExist())
		}
		return group.ID, nil

	case types.ObjectKindProject:
		project, err := h.GetProjectByRef(tx, ref)
		if err != nil {
			return "", errors.WithStack(err)
		}
		if project == nil {
			return "", util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("project with ref %q doesn't exists", ref), serrors.ProjectDoesNotExist())
		}
		return project.ID, nil

	default:
		return "", errors.Errorf("unknown object kind %q", objectKind)
	}
}

func (h *ActionHandler) getGlobalVisibility(tx *sql.Tx, curVisibility types.Visibility, parent *types.Parent) (types.Visibility, error) {
	curParent := parent
	if curVisibility == types.VisibilityPrivate {
		return curVisibility, nil
	}

	for curParent.Kind == types.ObjectKindProjectGroup {
		projectGroup, err := h.d.GetProjectGroupByID(tx, curParent.ID)
		if err != nil {
			return "", errors.WithStack(err)
		}
		if projectGroup.Visibility == types.VisibilityPrivate {
			return types.VisibilityPrivate, nil
		}

		curParent = &projectGroup.Parent
	}

	// check parent visibility
	if curParent.Kind == types.ObjectKindOrg {
		org, err := h.GetOrgByRef(tx, curParent.ID)
		if err != nil {
			return "", errors.WithStack(err)
		}
		if org.Visibility == types.VisibilityPrivate {
			return types.VisibilityPrivate, nil
		}
	}

	return curVisibility, nil
}
