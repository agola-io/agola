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

	"agola.io/agola/internal/db"
	"agola.io/agola/internal/services/configstore/common"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	sq "github.com/Masterminds/squirrel"
	errors "golang.org/x/xerrors"
)

var (
	orgSelect = sb.Select("org.id", "org.data").From("org")
	orgInsert = sb.Insert("org").Columns("id", "name", "data")

	orgmemberSelect = sb.Select("orgmember.id", "orgmember.data").From("orgmember")
	orgmemberInsert = sb.Insert("orgmember").Columns("id", "orgid", "userid", "role", "data")
)

func (r *ReadDB) insertOrg(tx *db.Tx, data []byte) error {
	org := types.Organization{}
	if err := json.Unmarshal(data, &org); err != nil {
		return errors.Errorf("failed to unmarshal org: %w", err)
	}
	r.log.Debugf("inserting org: %s", util.Dump(org))
	// poor man insert or update...
	if err := r.deleteOrg(tx, org.ID); err != nil {
		return err
	}
	q, args, err := orgInsert.Values(org.ID, org.Name, data).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err := tx.Exec(q, args...); err != nil {
		return errors.Errorf("failed to insert org: %w", err)
	}

	return nil
}

func (r *ReadDB) deleteOrg(tx *db.Tx, orgID string) error {
	if _, err := tx.Exec("delete from org where id = $1", orgID); err != nil {
		return errors.Errorf("failed to delete org: %w", err)
	}
	return nil
}

func (r *ReadDB) GetOrg(tx *db.Tx, orgRef string) (*types.Organization, error) {
	refType, err := common.ParseNameRef(orgRef)
	if err != nil {
		return nil, err
	}

	var org *types.Organization
	switch refType {
	case common.RefTypeID:
		org, err = r.GetOrgByID(tx, orgRef)
	case common.RefTypeName:
		org, err = r.GetOrgByName(tx, orgRef)
	}
	return org, err
}

func (r *ReadDB) GetOrgByID(tx *db.Tx, orgID string) (*types.Organization, error) {
	q, args, err := orgSelect.Where(sq.Eq{"id": orgID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	orgs, _, err := fetchOrgs(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(orgs) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(orgs) == 0 {
		return nil, nil
	}
	return orgs[0], nil
}

func (r *ReadDB) GetOrgByName(tx *db.Tx, name string) (*types.Organization, error) {
	q, args, err := orgSelect.Where(sq.Eq{"name": name}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	orgs, _, err := fetchOrgs(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(orgs) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(orgs) == 0 {
		return nil, nil
	}
	return orgs[0], nil
}

func getOrgsFilteredQuery(startOrgName string, limit int, asc bool) sq.SelectBuilder {
	fields := []string{"id", "data"}

	s := sb.Select(fields...).From("org as org")
	if asc {
		s = s.OrderBy("org.name asc")
	} else {
		s = s.OrderBy("org.name desc")
	}
	if startOrgName != "" {
		if asc {
			s = s.Where(sq.Gt{"org.name": startOrgName})
		} else {
			s = s.Where(sq.Lt{"org.name": startOrgName})
		}
	}
	if limit > 0 {
		s = s.Limit(uint64(limit))
	}

	return s
}

func (r *ReadDB) GetOrgs(tx *db.Tx, startOrgName string, limit int, asc bool) ([]*types.Organization, error) {
	var orgs []*types.Organization

	s := getOrgsFilteredQuery(startOrgName, limit, asc)
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}

	orgs, _, err = scanOrgs(rows)
	return orgs, err
}

func fetchOrgs(tx *db.Tx, q string, args ...interface{}) ([]*types.Organization, []string, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	return scanOrgs(rows)
}

func scanOrg(rows *sql.Rows, additionalFields ...interface{}) (*types.Organization, string, error) {
	var id string
	var data []byte
	if err := rows.Scan(&id, &data); err != nil {
		return nil, "", errors.Errorf("failed to scan rows: %w", err)
	}
	org := types.Organization{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &org); err != nil {
			return nil, "", errors.Errorf("failed to unmarshal org: %w", err)
		}
	}

	return &org, id, nil
}

func scanOrgs(rows *sql.Rows) ([]*types.Organization, []string, error) {
	orgs := []*types.Organization{}
	ids := []string{}
	for rows.Next() {
		org, id, err := scanOrg(rows)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		orgs = append(orgs, org)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return orgs, ids, nil
}

func (r *ReadDB) insertOrgMember(tx *db.Tx, data []byte) error {
	orgmember := types.OrganizationMember{}
	if err := json.Unmarshal(data, &orgmember); err != nil {
		return errors.Errorf("failed to unmarshal orgmember: %w", err)
	}
	r.log.Debugf("inserting orgmember: %s", util.Dump(orgmember))
	// poor man insert or update...
	if err := r.deleteOrgMember(tx, orgmember.ID); err != nil {
		return err
	}
	q, args, err := orgmemberInsert.Values(orgmember.ID, orgmember.OrganizationID, orgmember.UserID, orgmember.MemberRole, data).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err := tx.Exec(q, args...); err != nil {
		return errors.Errorf("failed to insert orgmember: %w", err)
	}

	return nil
}

func (r *ReadDB) deleteOrgMember(tx *db.Tx, orgmemberID string) error {
	if _, err := tx.Exec("delete from orgmember where id = $1", orgmemberID); err != nil {
		return errors.Errorf("failed to delete orgmember: %w", err)
	}
	return nil
}

func (r *ReadDB) GetOrgMemberByOrgUserID(tx *db.Tx, orgID, userID string) (*types.OrganizationMember, error) {
	q, args, err := orgmemberSelect.Where(sq.Eq{"orgmember.orgid": orgID, "orgmember.userid": userID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	oms, _, err := fetchOrgMembers(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(oms) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(oms) == 0 {
		return nil, nil
	}
	return oms[0], nil
}

func fetchOrgMembers(tx *db.Tx, q string, args ...interface{}) ([]*types.OrganizationMember, []string, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	return scanOrgMembers(rows)
}

func scanOrgMember(rows *sql.Rows, additionalFields ...interface{}) (*types.OrganizationMember, string, error) {
	var id string
	var data []byte
	if err := rows.Scan(&id, &data); err != nil {
		return nil, "", errors.Errorf("failed to scan rows: %w", err)
	}
	orgmember := types.OrganizationMember{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &orgmember); err != nil {
			return nil, "", errors.Errorf("failed to unmarshal org: %w", err)
		}
	}

	return &orgmember, id, nil
}

func scanOrgMembers(rows *sql.Rows) ([]*types.OrganizationMember, []string, error) {
	orgmembers := []*types.OrganizationMember{}
	ids := []string{}
	for rows.Next() {
		orgmember, id, err := scanOrgMember(rows)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		orgmembers = append(orgmembers, orgmember)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return orgmembers, ids, nil
}

type OrgUser struct {
	User *types.User
	Role types.MemberRole
}

// TODO(sgotti) implement cursor fetching
func (r *ReadDB) GetOrgUsers(tx *db.Tx, orgID string) ([]*OrgUser, error) {
	s := sb.Select("orgmember.data", "user.data").From("orgmember")
	s = s.Where(sq.Eq{"orgmember.orgid": orgID})
	s = s.Join("user on user.id = orgmember.userid")
	s = s.OrderBy("user.name")
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	orgusers := []*OrgUser{}
	for rows.Next() {
		var orgmember *types.OrganizationMember
		var user *types.User
		var orgmemberdata []byte
		var userdata []byte
		if err := rows.Scan(&orgmemberdata, &userdata); err != nil {
			return nil, errors.Errorf("failed to scan rows: %w", err)
		}
		if err := json.Unmarshal(orgmemberdata, &orgmember); err != nil {
			return nil, errors.Errorf("failed to unmarshal orgmember: %w", err)
		}
		if err := json.Unmarshal(userdata, &user); err != nil {
			return nil, errors.Errorf("failed to unmarshal org: %w", err)
		}

		orgusers = append(orgusers, &OrgUser{
			User: user,
			Role: orgmember.MemberRole,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return orgusers, nil
}

type UserOrg struct {
	Organization *types.Organization
	Role         types.MemberRole
}

// TODO(sgotti) implement cursor fetching
func (r *ReadDB) GetUserOrgs(tx *db.Tx, userID string) ([]*UserOrg, error) {
	s := sb.Select("orgmember.data", "org.data").From("orgmember")
	s = s.Where(sq.Eq{"orgmember.userid": userID})
	s = s.Join("org on org.id = orgmember.orgid")
	s = s.OrderBy("org.name")
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	userorgs := []*UserOrg{}
	for rows.Next() {
		var orgmember *types.OrganizationMember
		var org *types.Organization
		var orgmemberdata []byte
		var orgdata []byte
		if err := rows.Scan(&orgmemberdata, &orgdata); err != nil {
			return nil, errors.Errorf("failed to scan rows: %w", err)
		}
		if err := json.Unmarshal(orgmemberdata, &orgmember); err != nil {
			return nil, errors.Errorf("failed to unmarshal orgmember: %w", err)
		}
		if err := json.Unmarshal(orgdata, &org); err != nil {
			return nil, errors.Errorf("failed to unmarshal org: %w", err)
		}

		userorgs = append(userorgs, &UserOrg{
			Organization: org,
			Role:         orgmember.MemberRole,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return userorgs, nil
}
