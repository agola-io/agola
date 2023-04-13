package db

import (
	"context"
	stdsql "database/sql"
	"path"
	"strings"

	sq "github.com/huandu/go-sqlbuilder"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/configstore/common"
	"agola.io/agola/internal/services/configstore/db/objects"
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/services/configstore/types"
)

type DB struct {
	log zerolog.Logger
	sdb *sql.DB
}

func NewDB(log zerolog.Logger, sdb *sql.DB) (*DB, error) {
	return &DB{
		log: log,
		sdb: sdb,
	}, nil
}

func (d *DB) DBType() sql.Type {
	return d.sdb.Type()
}

func (d *DB) Do(ctx context.Context, f func(tx *sql.Tx) error) error {
	return errors.WithStack(d.sdb.Do(ctx, f))
}

func (d *DB) ObjectsInfo() []sqlg.ObjectInfo {
	return objects.ObjectsInfo
}

func (d *DB) Flavor() sq.Flavor {
	switch d.sdb.Type() {
	case sql.Postgres:
		return sq.PostgreSQL
	case sql.Sqlite3:
		return sq.SQLite
	}

	return sq.PostgreSQL
}

func (d *DB) exec(tx *sql.Tx, rq sq.Builder) (stdsql.Result, error) {
	q, args := rq.BuildWithFlavor(d.Flavor())
	// d.log.Debug().Msgf("q: %s, args: %s", q, util.Dump(args))

	r, err := tx.Exec(q, args...)
	return r, errors.WithStack(err)
}

func (d *DB) query(tx *sql.Tx, rq sq.Builder) (*stdsql.Rows, error) {
	q, args := rq.BuildWithFlavor(d.Flavor())
	// d.log.Debug().Msgf("start q: %s, args: %s", q, util.Dump(args))

	r, err := tx.Query(q, args...)
	// d.log.Debug().Msgf("end q: %s, args: %s", q, util.Dump(args))
	return r, errors.WithStack(err)
}

func mustSingleRow[T any](s []*T) (*T, error) {
	if len(s) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(s) == 0 {
		return nil, nil
	}

	return s[0], nil
}

func (d *DB) GetPath(tx *sql.Tx, objectKind types.ObjectKind, id string) (string, error) {
	var p string
	switch objectKind {
	case types.ObjectKindProjectGroup:
		projectGroup, err := d.GetProjectGroup(tx, id)
		if err != nil {
			return "", errors.WithStack(err)
		}
		if projectGroup == nil {
			return "", errors.Errorf("projectgroup with id %q doesn't exist", id)
		}
		p, err = d.GetProjectGroupPath(tx, projectGroup)
		if err != nil {
			return "", errors.WithStack(err)
		}
	case types.ObjectKindProject:
		project, err := d.GetProject(tx, id)
		if err != nil {
			return "", errors.WithStack(err)
		}
		if project == nil {
			return "", errors.Errorf("project with id %q doesn't exist", id)
		}
		p, err = d.GetProjectPath(tx, project)
		if err != nil {
			return "", errors.WithStack(err)
		}
	case types.ObjectKindOrg:
		org, err := d.GetOrg(tx, id)
		if err != nil {
			return "", errors.Wrapf(err, "failed to get org %q", id)
		}
		if org == nil {
			return "", errors.Errorf("cannot find org with id %q", id)
		}
		p = path.Join("org", org.Name)
	case types.ObjectKindUser:
		user, err := d.GetUser(tx, id)
		if err != nil {
			return "", errors.Wrapf(err, "failed to get user %q", id)
		}
		if user == nil {
			return "", errors.Errorf("cannot find user with id %q", id)
		}
		p = path.Join("user", user.Name)
	default:
		return "", errors.Errorf("config type %q doesn't provide a path", objectKind)
	}

	return p, nil
}

func (d *DB) GetRemoteSource(tx *sql.Tx, rsRef string) (*types.RemoteSource, error) {
	refType, err := common.ParseNameRef(rsRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var rs *types.RemoteSource
	switch refType {
	case common.RefTypeID:
		rs, err = d.GetRemoteSourceByID(tx, rsRef)
	case common.RefTypeName:
		rs, err = d.GetRemoteSourceByName(tx, rsRef)
	}
	return rs, errors.WithStack(err)
}

func (d *DB) GetRemoteSourceByID(tx *sql.Tx, remoteSourceID string) (*types.RemoteSource, error) {
	q := remoteSourceSelect()
	q.Where(q.E("id", remoteSourceID))
	remoteSources, _, err := d.fetchRemoteSources(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(remoteSources)
	return out, errors.WithStack(err)
}

func (d *DB) GetRemoteSourceByName(tx *sql.Tx, name string) (*types.RemoteSource, error) {
	q := remoteSourceSelect()
	q.Where(q.E("name", name))
	remoteSources, _, err := d.fetchRemoteSources(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(remoteSources)
	return out, errors.WithStack(err)
}

func getRemoteSourcesFilteredQuery(startRemoteSourceName string, limit int, asc bool) *sq.SelectBuilder {
	q := remoteSourceSelect()
	if asc {
		q = q.OrderBy("remotesource.name").Asc()
	} else {
		q = q.OrderBy("remotesource.name").Desc()
	}
	if startRemoteSourceName != "" {
		if asc {
			q = q.Where(q.G("remotesource.name", startRemoteSourceName))
		} else {
			q = q.Where(q.L("remotesource.name", startRemoteSourceName))
		}
	}
	if limit > 0 {
		q = q.Limit(limit)
	}

	return q
}

func (d *DB) GetRemoteSources(tx *sql.Tx, startRemoteSourceName string, limit int, asc bool) ([]*types.RemoteSource, error) {
	q := getRemoteSourcesFilteredQuery(startRemoteSourceName, limit, asc)
	remoteSources, _, err := d.fetchRemoteSources(tx, q)

	return remoteSources, errors.WithStack(err)
}

func (d *DB) GetUser(tx *sql.Tx, userRef string) (*types.User, error) {
	refType, err := common.ParseNameRef(userRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var user *types.User
	switch refType {
	case common.RefTypeID:
		user, err = d.GetUserByID(tx, userRef)
	case common.RefTypeName:
		user, err = d.GetUserByName(tx, userRef)
	}
	return user, errors.WithStack(err)
}

func (d *DB) GetUserByID(tx *sql.Tx, userID string) (*types.User, error) {
	q := userSelect()
	q.Where(q.E("id", userID))
	users, _, err := d.fetchUsers(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(users)
	return out, errors.WithStack(err)
}

func (d *DB) GetUserByName(tx *sql.Tx, name string) (*types.User, error) {
	q := userSelect()
	q.Where(q.E("name", name))
	users, _, err := d.fetchUsers(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(users)
	return out, errors.WithStack(err)
}

func (d *DB) GetUserTokens(tx *sql.Tx, userID string) ([]*types.UserToken, error) {
	q := userTokenSelect()
	q.Join("user_t", "usertoken.user_id = user_t.id").Where(q.E("user_t.id", userID))
	tokens, _, err := d.fetchUserTokens(tx, q)

	return tokens, errors.WithStack(err)
}

func (d *DB) GetUserToken(tx *sql.Tx, userID, tokenName string) (*types.UserToken, error) {
	q := userTokenSelect()
	q.Join("user_t", "usertoken.user_id = user_t.id")
	q.Where(q.E("user_t.id", userID), q.E("usertoken.name", tokenName))

	userTokens, _, err := d.fetchUserTokens(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(userTokens)
	return out, errors.WithStack(err)
}

func (d *DB) GetUserByTokenValue(tx *sql.Tx, tokenValue string) (*types.User, error) {
	q := userSelect()
	q = q.Join("usertoken", "usertoken.user_id = user_t.id")
	q = q.Where(q.E("usertoken.value", tokenValue))

	users, _, err := d.fetchUsers(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(users)
	return out, errors.WithStack(err)
}

func (d *DB) GetLinkedAccounts(tx *sql.Tx, linkedAccountsIDs []string) ([]*types.LinkedAccount, error) {
	q := linkedAccountSelect()
	q.Where(q.E("id", linkedAccountsIDs))
	linkedAccounts, _, err := d.fetchLinkedAccounts(tx, q)

	return linkedAccounts, errors.WithStack(err)
}

func (d *DB) GetLinkedAccount(tx *sql.Tx, linkedAccountID string) (*types.LinkedAccount, error) {
	q := linkedAccountSelect()
	q.Where(q.E("id", linkedAccountID))
	linkedAccounts, _, err := d.fetchLinkedAccounts(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(linkedAccounts)
	return out, errors.WithStack(err)
}

// func (d *DB) GetLinkedAccount(tx *sql.Tx, userID, linkedAccountID string) (*types.LinkedAccount, error) {
// 	q := linkedAccountSelect()
//	q..Eq{"id": linkedAccountID, "user_id": userID))
// 	linkedAccounts, _, err := d.fetchLinkedAccounts(tx, q)
// 	if err != nil {
// 		return nil, errors.WithStack(err)
// 	}
//
//	out, err := mustSingleRow(linkedAccounts)
//	return out, errors.WithStack(err)
// }

func (d *DB) GetUserLinkedAccounts(tx *sql.Tx, userID string) ([]*types.LinkedAccount, error) {
	q := linkedAccountSelect()
	q.Join("user_t", "linkedaccount.user_id = user_t.id").Where(q.E("user_t.id", userID))

	linkedAccounts, _, err := d.fetchLinkedAccounts(tx, q)

	return linkedAccounts, errors.WithStack(err)
}

func (d *DB) GetUserByLinkedAccount(tx *sql.Tx, linkedAccountID string) (*types.User, error) {
	q := userSelect()
	q = q.Join("linkedaccount", "linkedaccount.user_id = user_t.id")
	q = q.Where(q.E("linkedaccount.id", linkedAccountID))

	users, _, err := d.fetchUsers(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(users)
	return out, errors.WithStack(err)
}

func (d *DB) GetLinkedAccountByRemoteUserIDandSource(tx *sql.Tx, remoteUserID, remoteSourceID string) (*types.LinkedAccount, error) {
	q := linkedAccountSelect()
	q.Where(q.E("linkedaccount.remote_user_id", remoteUserID), q.E("linkedaccount.remote_source_id", remoteSourceID))

	linkedAccounts, _, err := d.fetchLinkedAccounts(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(linkedAccounts)
	return out, errors.WithStack(err)
}

// func (d *DB) GetUserByLinkedAccountRemoteUserIDandSource(tx *sql.Tx, remoteUserID, remoteSourceID string) (*types.User, error) {
// 	q := userSelect()
// 	q = q.Join("linkedaccount", "linkedaccount.user_id = user_t.id")
// 	q = q.Where(q.E("linkedaccount.remote_user_id", remoteUserID), q.E("linkedaccount.remote_source_id", remoteSourceID))

// 	users, _, err := d.fetchUsers(tx, q)
// 	if err != nil {
// 		return nil, errors.WithStack(err)
// 	}

//	out, err := mustSingleRow(users)
//	return out, errors.WithStack(err)
// }

func getUsersFilteredQuery(startUserName string, limit int, asc bool) *sq.SelectBuilder {
	q := userSelect()
	if asc {
		q = q.OrderBy("user_t.name").Asc()
	} else {
		q = q.OrderBy("user_t.name").Desc()
	}
	if startUserName != "" {
		if asc {
			q = q.Where(q.G("user_t.name", startUserName))
		} else {
			q = q.Where(q.L("user_t.name", startUserName))
		}
	}
	if limit > 0 {
		q = q.Limit(limit)
	}

	return q
}

func (d *DB) GetUsers(tx *sql.Tx, startUserName string, limit int, asc bool) ([]*types.User, error) {
	q := getUsersFilteredQuery(startUserName, limit, asc)
	users, _, err := d.fetchUsers(tx, q)

	return users, errors.WithStack(err)
}

func (d *DB) GetOrg(tx *sql.Tx, orgRef string) (*types.Organization, error) {
	refType, err := common.ParseNameRef(orgRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var org *types.Organization
	switch refType {
	case common.RefTypeID:
		org, err = d.GetOrgByID(tx, orgRef)
	case common.RefTypeName:
		org, err = d.GetOrgByName(tx, orgRef)
	}
	return org, errors.WithStack(err)
}

func (d *DB) GetOrgByID(tx *sql.Tx, orgID string) (*types.Organization, error) {
	q := organizationSelect()
	q.Where(q.E("id", orgID))
	orgs, _, err := d.fetchOrganizations(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(orgs)
	return out, errors.WithStack(err)
}

func (d *DB) GetOrgByName(tx *sql.Tx, name string) (*types.Organization, error) {
	q := organizationSelect()
	q.Where(q.E("name", name))
	orgs, _, err := d.fetchOrganizations(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(orgs)
	return out, errors.WithStack(err)
}

func getOrgsFilteredQuery(startOrgName string, limit int, asc bool) *sq.SelectBuilder {
	q := organizationSelect()
	if asc {
		q = q.OrderBy("name").Asc()
	} else {
		q = q.OrderBy("name").Desc()
	}
	if startOrgName != "" {
		if asc {
			q = q.Where(q.G("name", startOrgName))
		} else {
			q = q.Where(q.L("name", startOrgName))
		}
	}
	if limit > 0 {
		q = q.Limit(limit)
	}

	return q
}

func (d *DB) GetOrgs(tx *sql.Tx, startOrgName string, limit int, asc bool) ([]*types.Organization, error) {
	q := getOrgsFilteredQuery(startOrgName, limit, asc)
	orgs, _, err := d.fetchOrganizations(tx, q)

	return orgs, errors.WithStack(err)
}

func (d *DB) GetOrgMemberByOrgUserID(tx *sql.Tx, orgID, userID string) (*types.OrganizationMember, error) {
	q := organizationMemberSelect()
	q.Where(q.E("orgmember.organization_id", orgID), q.E("orgmember.user_id", userID))

	oms, _, err := d.fetchOrganizationMembers(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(oms)
	return out, errors.WithStack(err)
}

type OrgUser struct {
	User *types.User
	Role types.MemberRole
}

// TODO(sgotti) implement cursor fetching
func (d *DB) GetOrgUsers(tx *sql.Tx, orgID string) ([]*OrgUser, error) {
	cols := organizationMemberSelectColumns()
	cols = append(cols, userSelectColumns()...)

	q := sq.Select(cols...).From("orgmember")
	q = q.Join("user_t", "user_t.id = orgmember.user_id")
	q = q.Where(q.E("orgmember.organization_id", orgID))
	q = q.OrderBy("user_t.name")

	rows, err := d.query(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer rows.Close()

	orgusers := []*OrgUser{}
	for rows.Next() {
		orgMemberCols := d.OrganizationMemberArray()
		userCols := d.UserArray()
		if err := d.scanArray(rows, orgMemberCols, userCols); err != nil {
			return nil, errors.Wrapf(err, "failed to scan rows")
		}

		orgMember, _, err := d.OrganizationMemberFromArray(orgMemberCols, tx.ID())
		if err != nil {
			return nil, errors.Wrapf(err, "failed to fetch org")
		}

		user, _, err := d.UserFromArray(userCols, tx.ID())
		if err != nil {
			return nil, errors.Wrapf(err, "failed to fetch user")
		}

		orgusers = append(orgusers, &OrgUser{
			User: user,
			Role: orgMember.MemberRole,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.WithStack(err)
	}

	return orgusers, nil
}

type UserOrg struct {
	Organization *types.Organization
	Role         types.MemberRole
}

// TODO(sgotti) implement cursor fetching
func (d *DB) GetUserOrgs(tx *sql.Tx, userID string) ([]*UserOrg, error) {
	cols := organizationMemberSelectColumns()
	cols = append(cols, organizationSelectColumns()...)

	q := sq.Select(cols...).From("orgmember")
	q = q.Where(q.E("orgmember.user_id", userID))
	q = q.Join("organization", "organization.id = orgmember.organization_id")
	q = q.OrderBy("organization.name")

	rows, err := d.query(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer rows.Close()

	userorgs := []*UserOrg{}
	for rows.Next() {
		orgMemberCols := d.OrganizationMemberArray()
		organizationCols := d.OrganizationArray()
		if err := d.scanArray(rows, orgMemberCols, organizationCols); err != nil {
			return nil, errors.Wrapf(err, "failed to scan rows")
		}

		orgMember, _, err := d.OrganizationMemberFromArray(orgMemberCols, tx.ID())
		if err != nil {
			return nil, errors.Wrapf(err, "failed to fetch org")
		}

		org, _, err := d.OrganizationFromArray(organizationCols, tx.ID())
		if err != nil {
			return nil, errors.Wrapf(err, "failed to fetch org")
		}

		userorgs = append(userorgs, &UserOrg{
			Organization: org,
			Role:         orgMember.MemberRole,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.WithStack(err)
	}

	return userorgs, nil
}

type Element struct {
	ID         string
	Name       string
	Kind       types.ObjectKind
	ParentKind types.ObjectKind
	ParentID   string
}

func (d *DB) GetProjectGroupHierarchy(tx *sql.Tx, projectGroup *types.ProjectGroup) ([]*Element, error) {
	projectGroupID := projectGroup.Parent.ID
	elements := []*Element{
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
		projectGroup, err = d.GetProjectGroup(tx, projectGroupID)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get project group %q", projectGroupID)
		}
		if projectGroup == nil {
			return nil, errors.Errorf("project group %q doesn't exist", projectGroupID)
		}
		elements = append([]*Element{
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

func (d *DB) GetProjectGroupPath(tx *sql.Tx, group *types.ProjectGroup) (string, error) {
	var p string

	groups, err := d.GetProjectGroupHierarchy(tx, group)
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
		p, err = d.GetPath(tx, rootGroupType, rootGroupID)
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

func (d *DB) GetProjectGroupOwnerID(tx *sql.Tx, group *types.ProjectGroup) (types.ObjectKind, string, error) {
	groups, err := d.GetProjectGroupHierarchy(tx, group)
	if err != nil {
		return "", "", errors.WithStack(err)
	}

	rootGroupType := groups[0].ParentKind
	rootGroupID := groups[0].ParentID
	return rootGroupType, rootGroupID, nil
}

func (d *DB) GetProjectGroup(tx *sql.Tx, projectGroupRef string) (*types.ProjectGroup, error) {
	groupRef, err := common.ParsePathRef(projectGroupRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var group *types.ProjectGroup
	switch groupRef {
	case common.RefTypeID:
		group, err = d.GetProjectGroupByID(tx, projectGroupRef)
	case common.RefTypePath:
		group, err = d.GetProjectGroupByPath(tx, projectGroupRef)
	}
	return group, errors.WithStack(err)
}

func (d *DB) GetProjectGroupByID(tx *sql.Tx, projectGroupID string) (*types.ProjectGroup, error) {
	q := projectGroupSelect()
	q.Where(q.E("id", projectGroupID))
	projectGroups, _, err := d.fetchProjectGroups(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(projectGroups)
	return out, errors.WithStack(err)
}

func (d *DB) GetProjectGroupByName(tx *sql.Tx, parentID, name string) (*types.ProjectGroup, error) {
	q := projectGroupSelect()
	q.Where(q.E("parent_id", parentID), q.E("name", name))
	projectGroups, _, err := d.fetchProjectGroups(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(projectGroups)
	return out, errors.WithStack(err)
}

func (d *DB) GetProjectGroupByPath(tx *sql.Tx, projectGroupPath string) (*types.ProjectGroup, error) {
	parts := strings.Split(projectGroupPath, "/")
	if len(parts) < 2 {
		return nil, errors.Errorf("wrong project group path: %q", projectGroupPath)
	}
	var parentID string
	switch parts[0] {
	case "org":
		org, err := d.GetOrgByName(tx, parts[1])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get org %q", parts[1])
		}
		if org == nil {
			return nil, errors.Errorf("cannot find org with name %q", parts[1])
		}
		parentID = org.ID
	case "user":
		user, err := d.GetUserByName(tx, parts[1])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get user %q", parts[1])
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
		projectGroup, err = d.GetProjectGroupByName(tx, parentID, projectGroupName)
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

func (d *DB) GetProjectGroupSubgroups(tx *sql.Tx, parentID string) ([]*types.ProjectGroup, error) {
	q := projectGroupSelect()
	q.Where(q.E("parent_id", parentID))
	projectGroups, _, err := d.fetchProjectGroups(tx, q)

	return projectGroups, errors.WithStack(err)
}

func (d *DB) GetProjectPath(tx *sql.Tx, project *types.Project) (string, error) {
	pgroup, err := d.GetProjectGroup(tx, project.Parent.ID)
	if err != nil {
		return "", errors.WithStack(err)
	}
	if pgroup == nil {
		return "", errors.Errorf("parent group %q for project %q doesn't exist", project.Parent.ID, project.ID)
	}
	p, err := d.GetProjectGroupPath(tx, pgroup)
	if err != nil {
		return "", errors.WithStack(err)
	}

	p = path.Join(p, project.Name)

	return p, nil
}

func (d *DB) GetProjectOwnerID(tx *sql.Tx, project *types.Project) (types.ObjectKind, string, error) {
	pgroup, err := d.GetProjectGroup(tx, project.Parent.ID)
	if err != nil {
		return "", "", errors.WithStack(err)
	}
	if pgroup == nil {
		return "", "", errors.Errorf("parent group %q for project %q doesn't exist", project.Parent.ID, project.ID)
	}
	return d.GetProjectGroupOwnerID(tx, pgroup)
}

func (d *DB) GetProject(tx *sql.Tx, projectRef string) (*types.Project, error) {
	projectRefType, err := common.ParsePathRef(projectRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var project *types.Project
	switch projectRefType {
	case common.RefTypeID:
		project, err = d.GetProjectByID(tx, projectRef)
	case common.RefTypePath:
		project, err = d.GetProjectByPath(tx, projectRef)
	}
	return project, errors.WithStack(err)
}

func (d *DB) GetProjectByID(tx *sql.Tx, projectID string) (*types.Project, error) {
	q := projectSelect()
	q.Where(q.E("id", projectID))

	projects, _, err := d.fetchProjects(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(projects)
	return out, errors.WithStack(err)
}

func (d *DB) GetProjectByName(tx *sql.Tx, parentID, name string) (*types.Project, error) {
	q := projectSelect()
	q.Where(q.E("parent_id", parentID), q.E("name", name))

	projects, _, err := d.fetchProjects(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(projects)
	return out, errors.WithStack(err)
}

func (d *DB) GetProjectByPath(tx *sql.Tx, projectPath string) (*types.Project, error) {
	if len(strings.Split(projectPath, "/")) < 3 {
		return nil, errors.Errorf("wrong project path: %q", projectPath)
	}

	projectGroupPath := path.Dir(projectPath)
	projectName := path.Base(projectPath)
	projectGroup, err := d.GetProjectGroupByPath(tx, projectGroupPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get project group %q", projectGroupPath)
	}
	if projectGroup == nil {
		return nil, nil
	}

	project, err := d.GetProjectByName(tx, projectGroup.ID, projectName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get project group %q", projectName)
	}

	return project, nil
}

func (d *DB) GetProjectGroupProjects(tx *sql.Tx, parentID string) ([]*types.Project, error) {
	q := projectSelect()
	q.Where(q.E("parent_id", parentID))
	projects, _, err := d.fetchProjects(tx, q)

	return projects, errors.WithStack(err)
}

func (d *DB) GetSecretByID(tx *sql.Tx, secretID string) (*types.Secret, error) {
	q := secretSelect()
	q.Where(q.E("id", secretID))
	secrets, _, err := d.fetchSecrets(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(secrets)
	return out, errors.WithStack(err)
}

func (d *DB) GetSecretByName(tx *sql.Tx, parentID, name string) (*types.Secret, error) {
	q := secretSelect()
	q.Where(q.E("parent_id", parentID), q.E("name", name))
	secrets, _, err := d.fetchSecrets(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(secrets)
	return out, errors.WithStack(err)
}

func (d *DB) GetSecrets(tx *sql.Tx, parentID string) ([]*types.Secret, error) {
	q := secretSelect()
	q.Where(q.E("parent_id", parentID))
	secrets, _, err := d.fetchSecrets(tx, q)
	return secrets, errors.WithStack(err)
}

func (d *DB) GetSecretTree(tx *sql.Tx, parentKind types.ObjectKind, parentID, name string) (*types.Secret, error) {
	for parentKind == types.ObjectKindProjectGroup || parentKind == types.ObjectKindProject {
		secret, err := d.GetSecretByName(tx, parentID, name)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get secret with name %q", name)
		}
		if secret != nil {
			return secret, nil
		}

		switch parentKind {
		case types.ObjectKindProjectGroup:
			projectGroup, err := d.GetProjectGroup(tx, parentID)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if projectGroup == nil {
				return nil, errors.Errorf("projectgroup with id %q doesn't exist", parentID)
			}
			parentKind = projectGroup.Parent.Kind
			parentID = projectGroup.Parent.ID
		case types.ObjectKindProject:
			project, err := d.GetProject(tx, parentID)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if project == nil {
				return nil, errors.Errorf("project with id %q doesn't exist", parentID)
			}
			parentKind = project.Parent.Kind
			parentID = project.Parent.ID
		}
	}

	return nil, nil
}

func (d *DB) GetSecretsTree(tx *sql.Tx, parentKind types.ObjectKind, parentID string) ([]*types.Secret, error) {
	allSecrets := []*types.Secret{}

	for parentKind == types.ObjectKindProjectGroup || parentKind == types.ObjectKindProject {
		secrets, err := d.GetSecrets(tx, parentID)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get secrets for %s %q", parentKind, parentID)
		}
		allSecrets = append(allSecrets, secrets...)

		switch parentKind {
		case types.ObjectKindProjectGroup:
			projectGroup, err := d.GetProjectGroup(tx, parentID)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if projectGroup == nil {
				return nil, errors.Errorf("projectgroup with id %q doesn't exist", parentID)
			}
			parentKind = projectGroup.Parent.Kind
			parentID = projectGroup.Parent.ID
		case types.ObjectKindProject:
			project, err := d.GetProject(tx, parentID)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if project == nil {
				return nil, errors.Errorf("project with id %q doesn't exist", parentID)
			}
			parentKind = project.Parent.Kind
			parentID = project.Parent.ID
		}
	}

	return allSecrets, nil
}

func (d *DB) GetVariableByID(tx *sql.Tx, variableID string) (*types.Variable, error) {
	q := variableSelect()
	q.Where(q.E("id", variableID))
	variables, _, err := d.fetchVariables(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(variables)
	return out, errors.WithStack(err)
}

func (d *DB) GetVariableByName(tx *sql.Tx, parentID, name string) (*types.Variable, error) {
	q := variableSelect()
	q.Where(q.E("parent_id", parentID), q.E("name", name))
	variables, _, err := d.fetchVariables(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(variables)
	return out, errors.WithStack(err)
}

func (d *DB) GetVariables(tx *sql.Tx, parentID string) ([]*types.Variable, error) {
	q := variableSelect()
	q.Where(q.E("parent_id", parentID))
	variables, _, err := d.fetchVariables(tx, q)
	return variables, errors.WithStack(err)
}

func (d *DB) GetVariablesTree(tx *sql.Tx, parentKind types.ObjectKind, parentID string) ([]*types.Variable, error) {
	allVariables := []*types.Variable{}

	for parentKind == types.ObjectKindProjectGroup || parentKind == types.ObjectKindProject {
		vars, err := d.GetVariables(tx, parentID)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get variables for %s %q", parentKind, parentID)
		}
		allVariables = append(allVariables, vars...)

		switch parentKind {
		case types.ObjectKindProjectGroup:
			projectGroup, err := d.GetProjectGroup(tx, parentID)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if projectGroup == nil {
				return nil, errors.Errorf("projectgroup with id %q doesn't exist", parentID)
			}
			parentKind = projectGroup.Parent.Kind
			parentID = projectGroup.Parent.ID
		case types.ObjectKindProject:
			project, err := d.GetProject(tx, parentID)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if project == nil {
				return nil, errors.Errorf("project with id %q doesn't exist", parentID)
			}
			parentKind = project.Parent.Kind
			parentID = project.Parent.ID
		}
	}

	return allVariables, nil
}

// Test only functions
func (d *DB) GetAllProjects(tx *sql.Tx) ([]*types.Project, error) {
	q := projectSelect()
	q.OrderBy("id")
	projects, _, err := d.fetchProjects(tx, q)

	return projects, errors.WithStack(err)
}

func (d *DB) GetAllProjectGroups(tx *sql.Tx) ([]*types.ProjectGroup, error) {
	q := projectGroupSelect()
	q.OrderBy("id")
	projectGroups, _, err := d.fetchProjectGroups(tx, q)

	return projectGroups, errors.WithStack(err)
}

func (d *DB) GetAllSecrets(tx *sql.Tx) ([]*types.Secret, error) {
	q := secretSelect()
	q.OrderBy("id")
	secrets, _, err := d.fetchSecrets(tx, q)

	return secrets, errors.WithStack(err)
}

func (d *DB) GetAllVariables(tx *sql.Tx) ([]*types.Variable, error) {
	q := variableSelect()
	q.OrderBy("id")
	variables, _, err := d.fetchVariables(tx, q)

	return variables, errors.WithStack(err)
}

func (d *DB) GetOrgInvitations(tx *sql.Tx, orgID string) ([]*types.OrgInvitation, error) {
	q := orgInvitationSelect()
	q.Where(q.E("organization_id", orgID))
	orgInvitations, _, err := d.fetchOrgInvitations(tx, q)

	return orgInvitations, errors.WithStack(err)
}

func (d *DB) GetOrgInvitationByOrgUserID(tx *sql.Tx, orgID, userID string) (*types.OrgInvitation, error) {
	q := orgInvitationSelect()
	q.Where(q.E("organization_id", orgID), q.E("user_id", userID))

	orgInvitations, _, err := d.fetchOrgInvitations(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := mustSingleRow(orgInvitations)
	return out, errors.WithStack(err)
}

func (d *DB) GetOrgInvitationByUserID(tx *sql.Tx, userID string) ([]*types.OrgInvitation, error) {
	q := orgInvitationSelect()
	q.Where(q.E("user_id", userID))

	orgInvitations, _, err := d.fetchOrgInvitations(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return orgInvitations, errors.WithStack(err)
}
