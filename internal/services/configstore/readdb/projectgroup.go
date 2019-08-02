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

package readdb

import (
	"database/sql"
	"encoding/json"
	"path"
	"strings"

	"agola.io/agola/internal/db"
	"agola.io/agola/internal/services/configstore/common"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	sq "github.com/Masterminds/squirrel"
	errors "golang.org/x/xerrors"
)

var (
	projectgroupSelect = sb.Select("id", "data").From("projectgroup")
	projectgroupInsert = sb.Insert("projectgroup").Columns("id", "name", "parentid", "parenttype", "data")
)

func (r *ReadDB) insertProjectGroup(tx *db.Tx, data []byte) error {
	var group *types.ProjectGroup
	if err := json.Unmarshal(data, &group); err != nil {
		return errors.Errorf("failed to unmarshal group: %w", err)
	}

	// poor man insert or update...
	if err := r.deleteProjectGroup(tx, group.ID); err != nil {
		return err
	}
	q, args, err := projectgroupInsert.Values(group.ID, group.Name, group.Parent.ID, group.Parent.Type, data).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err = tx.Exec(q, args...); err != nil {
		return errors.Errorf("failed to insert group: %w", err)
	}

	return nil
}

func (r *ReadDB) deleteProjectGroup(tx *db.Tx, id string) error {
	// poor man insert or update...
	if _, err := tx.Exec("delete from projectgroup where id = $1", id); err != nil {
		return errors.Errorf("failed to delete group: %w", err)
	}
	return nil
}

type Element struct {
	ID         string
	Name       string
	Type       types.ConfigType
	ParentType types.ConfigType
	ParentID   string
}

func (r *ReadDB) GetProjectGroupHierarchy(tx *db.Tx, projectGroup *types.ProjectGroup) ([]*Element, error) {
	projectGroupID := projectGroup.Parent.ID
	elements := []*Element{
		{
			ID:         projectGroup.ID,
			Name:       projectGroup.Name,
			Type:       types.ConfigTypeProjectGroup,
			ParentType: projectGroup.Parent.Type,
			ParentID:   projectGroup.Parent.ID,
		},
	}

	for projectGroup.Parent.Type == types.ConfigTypeProjectGroup {
		var err error
		projectGroup, err = r.GetProjectGroup(tx, projectGroupID)
		if err != nil {
			return nil, errors.Errorf("failed to get project group %q: %w", projectGroupID, err)
		}
		if projectGroup == nil {
			return nil, errors.Errorf("project group %q doesn't exist", projectGroupID)
		}
		elements = append([]*Element{
			{
				ID:         projectGroup.ID,
				Name:       projectGroup.Name,
				Type:       types.ConfigTypeProjectGroup,
				ParentType: projectGroup.Parent.Type,
				ParentID:   projectGroup.Parent.ID,
			},
		}, elements...)
		projectGroupID = projectGroup.Parent.ID
	}

	return elements, nil
}

func (r *ReadDB) GetProjectGroupPath(tx *db.Tx, group *types.ProjectGroup) (string, error) {
	var p string

	groups, err := r.GetProjectGroupHierarchy(tx, group)
	if err != nil {
		return "", err
	}

	rootGroupType := groups[0].ParentType
	rootGroupID := groups[0].ParentID
	switch rootGroupType {
	case types.ConfigTypeOrg:
		fallthrough
	case types.ConfigTypeUser:
		var err error
		p, err = r.GetPath(tx, rootGroupType, rootGroupID)
		if err != nil {
			return "", err
		}
	default:
		return "", errors.Errorf("invalid root group type %q", rootGroupType)
	}

	for _, group := range groups {
		p = path.Join(p, group.Name)
	}

	return p, nil
}

func (r *ReadDB) GetProjectGroupOwnerID(tx *db.Tx, group *types.ProjectGroup) (types.ConfigType, string, error) {
	groups, err := r.GetProjectGroupHierarchy(tx, group)
	if err != nil {
		return "", "", err
	}

	rootGroupType := groups[0].ParentType
	rootGroupID := groups[0].ParentID
	return rootGroupType, rootGroupID, nil
}

func (r *ReadDB) GetProjectGroup(tx *db.Tx, projectGroupRef string) (*types.ProjectGroup, error) {
	groupRef, err := common.ParsePathRef(projectGroupRef)
	if err != nil {
		return nil, err
	}

	var group *types.ProjectGroup
	switch groupRef {
	case common.RefTypeID:
		group, err = r.GetProjectGroupByID(tx, projectGroupRef)
	case common.RefTypePath:
		group, err = r.GetProjectGroupByPath(tx, projectGroupRef)
	}
	return group, err
}

func (r *ReadDB) GetProjectGroupByID(tx *db.Tx, projectGroupID string) (*types.ProjectGroup, error) {
	q, args, err := projectgroupSelect.Where(sq.Eq{"id": projectGroupID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	projectGroups, _, err := fetchProjectGroups(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(projectGroups) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(projectGroups) == 0 {
		return nil, nil
	}
	return projectGroups[0], nil
}

func (r *ReadDB) GetProjectGroupByName(tx *db.Tx, parentID, name string) (*types.ProjectGroup, error) {
	q, args, err := projectgroupSelect.Where(sq.Eq{"parentid": parentID, "name": name}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	projectGroups, _, err := fetchProjectGroups(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(projectGroups) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(projectGroups) == 0 {
		return nil, nil
	}
	return projectGroups[0], nil
}

func (r *ReadDB) GetProjectGroupByPath(tx *db.Tx, projectGroupPath string) (*types.ProjectGroup, error) {
	parts := strings.Split(projectGroupPath, "/")
	if len(parts) < 2 {
		return nil, errors.Errorf("wrong project group path: %q", projectGroupPath)
	}
	var parentID string
	switch parts[0] {
	case "org":
		org, err := r.GetOrgByName(tx, parts[1])
		if err != nil {
			return nil, errors.Errorf("failed to get org %q: %w", parts[1], err)
		}
		if org == nil {
			return nil, errors.Errorf("cannot find org with name %q", parts[1])
		}
		parentID = org.ID
	case "user":
		user, err := r.GetUserByName(tx, parts[1])
		if err != nil {
			return nil, errors.Errorf("failed to get user %q: %w", parts[1], err)
		}
		if user == nil {
			return nil, errors.Errorf("cannot find user with name %q", parts[1])
		}
		parentID = user.ID
	default:
		return nil, errors.Errorf("wrong project group path: %q", projectGroupPath)
	}

	var projectGroup *types.ProjectGroup
	// add root project group (empty name)
	for _, projectGroupName := range append([]string{""}, parts[2:]...) {
		var err error
		projectGroup, err = r.GetProjectGroupByName(tx, parentID, projectGroupName)
		if err != nil {
			return nil, errors.Errorf("failed to get project group %q: %w", projectGroupName, err)
		}
		if projectGroup == nil {
			return nil, nil
		}
		parentID = projectGroup.ID
	}

	return projectGroup, nil
}

func (r *ReadDB) GetProjectGroupSubgroups(tx *db.Tx, parentID string) ([]*types.ProjectGroup, error) {
	var projectGroups []*types.ProjectGroup

	q, args, err := projectgroupSelect.Where(sq.Eq{"parentid": parentID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	projectGroups, _, err = fetchProjectGroups(tx, q, args...)
	return projectGroups, err
}

func fetchProjectGroups(tx *db.Tx, q string, args ...interface{}) ([]*types.ProjectGroup, []string, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	return scanProjectGroups(rows)
}

func scanProjectGroup(rows *sql.Rows, additionalFields ...interface{}) (*types.ProjectGroup, string, error) {
	var id string
	var data []byte
	if err := rows.Scan(&id, &data); err != nil {
		return nil, "", errors.Errorf("failed to scan rows: %w", err)
	}
	group := types.ProjectGroup{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &group); err != nil {
			return nil, "", errors.Errorf("failed to unmarshal group: %w", err)
		}
	}

	return &group, id, nil
}

func scanProjectGroups(rows *sql.Rows) ([]*types.ProjectGroup, []string, error) {
	projectGroups := []*types.ProjectGroup{}
	ids := []string{}
	for rows.Next() {
		p, id, err := scanProjectGroup(rows)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		projectGroups = append(projectGroups, p)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return projectGroups, ids, nil
}
