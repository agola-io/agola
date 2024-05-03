package db

import (
	"context"
	stdsql "database/sql"

	sq "github.com/huandu/go-sqlbuilder"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/configstore/common"
	"agola.io/agola/internal/services/configstore/db/objects"
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/services/configstore/types"
)

//go:generate ../../../../tools/bin/dbgenerator -type db -component configstore

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

func (d *DB) DB() *sql.DB {
	return d.sdb
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

func getRemoteSourcesFilteredQuery(startRemoteSourceName string, limit int, sortDirection types.SortDirection) *sq.SelectBuilder {
	q := remoteSourceSelect()
	q = q.OrderBy("remotesource.name")
	switch sortDirection {
	case types.SortDirectionAsc:
		q = q.Asc()
	case types.SortDirectionDesc:
		q = q.Desc()
	}
	if startRemoteSourceName != "" {
		switch sortDirection {
		case types.SortDirectionAsc:
			q = q.Where(q.G("remotesource.name", startRemoteSourceName))
		case types.SortDirectionDesc:
			q = q.Where(q.L("remotesource.name", startRemoteSourceName))
		}
	}
	if limit > 0 {
		q = q.Limit(limit)
	}

	return q
}

func (d *DB) GetRemoteSources(tx *sql.Tx, startRemoteSourceName string, limit int, sortDirection types.SortDirection) ([]*types.RemoteSource, error) {
	q := getRemoteSourcesFilteredQuery(startRemoteSourceName, limit, sortDirection)
	remoteSources, _, err := d.fetchRemoteSources(tx, q)

	return remoteSources, errors.WithStack(err)
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

func (d *DB) DeleteUserTokensByUserID(tx *sql.Tx, userID string) error {
	q := sq.NewDeleteBuilder()
	q.DeleteFrom("usertoken").Where(q.E("user_id", userID))
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrap(err, "failed to delete usertoken")
	}

	return nil
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

func (d *DB) DeleteLinkedAccountsByUserID(tx *sql.Tx, userID string) error {
	q := sq.NewDeleteBuilder()
	q.DeleteFrom("linkedaccount").Where(q.E("user_id", userID))
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrap(err, "failed to delete linkedaccount")
	}

	return nil
}

func getUsersFilteredQuery(startUserName string, limit int, sortDirection types.SortDirection) *sq.SelectBuilder {
	q := userSelect()
	q = q.OrderBy("user_t.name")
	switch sortDirection {
	case types.SortDirectionAsc:
		q = q.Asc()
	case types.SortDirectionDesc:
		q = q.Desc()
	}
	if startUserName != "" {
		switch sortDirection {
		case types.SortDirectionAsc:
			q = q.Where(q.G("user_t.name", startUserName))
		case types.SortDirectionDesc:
			q = q.Where(q.L("user_t.name", startUserName))
		}
	}
	if limit > 0 {
		q = q.Limit(limit)
	}

	return q
}

func (d *DB) GetUsers(tx *sql.Tx, startUserName string, limit int, sortDirection types.SortDirection) ([]*types.User, error) {
	q := getUsersFilteredQuery(startUserName, limit, sortDirection)
	users, _, err := d.fetchUsers(tx, q)

	return users, errors.WithStack(err)
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

func getOrgsFilteredQuery(startOrgName string, visibilities []types.Visibility, limit int, sortDirection types.SortDirection) *sq.SelectBuilder {
	q := organizationSelect()
	q = q.OrderBy("name")
	switch sortDirection {
	case types.SortDirectionAsc:
		q = q.Asc()
	case types.SortDirectionDesc:
		q = q.Desc()
	}
	if startOrgName != "" {
		switch sortDirection {
		case types.SortDirectionAsc:
			q = q.Where(q.G("name", startOrgName))
		case types.SortDirectionDesc:
			q = q.Where(q.L("name", startOrgName))
		}
	}

	if len(visibilities) > 0 {
		q.Where(q.In("visibility", sq.Flatten(visibilities)...))
	}

	if limit > 0 {
		q = q.Limit(limit)
	}

	return q
}

func (d *DB) GetOrgs(tx *sql.Tx, startOrgName string, visibilities []types.Visibility, limit int, sortDirection types.SortDirection) ([]*types.Organization, error) {
	q := getOrgsFilteredQuery(startOrgName, visibilities, limit, sortDirection)
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

func (d *DB) GetOrgMemberByUserID(tx *sql.Tx, userID string) ([]*types.OrganizationMember, error) {
	q := organizationMemberSelect()
	q.Where(q.E("orgmember.user_id", userID))

	oms, _, err := d.fetchOrganizationMembers(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return oms, errors.WithStack(err)
}

func (d *DB) DeleteOrgMembersByOrgID(tx *sql.Tx, orgID string) error {
	q := sq.NewDeleteBuilder()
	q.DeleteFrom("orgmember").Where(q.E("organization_id", orgID))
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrap(err, "failed to delete orgmember")
	}

	return nil
}

func (d *DB) DeleteOrgMembersByUserID(tx *sql.Tx, userID string) error {
	q := sq.NewDeleteBuilder()
	q.DeleteFrom("orgmember").Where(q.E("user_id", userID))
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrap(err, "failed to delete orgmember")
	}

	return nil
}

type OrgUser struct {
	User *types.User
	Role types.MemberRole
}

func (d *DB) GetOrgMembers(tx *sql.Tx, orgID string, startUserName string, limit int, sortDirection types.SortDirection) ([]*OrgUser, error) {
	cols := organizationMemberSelectColumns()
	cols = append(cols, userSelectColumns()...)

	q := sq.Select(cols...).From("orgmember")
	q = q.Join("user_t", "user_t.id = orgmember.user_id")
	q = q.Where(q.E("orgmember.organization_id", orgID))
	q = q.OrderBy("user_t.name")
	switch sortDirection {
	case types.SortDirectionAsc:
		q.Asc()
	case types.SortDirectionDesc:
		q.Desc()
	}

	if startUserName != "" {
		switch sortDirection {
		case types.SortDirectionAsc:
			q = q.Where(q.G("user_t.name", startUserName))
		case types.SortDirectionDesc:
			q = q.Where(q.L("user_t.name", startUserName))
		}
	}

	if limit > 0 {
		q = q.Limit(limit)
	}

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

func (d *DB) GetUserOrg(tx *sql.Tx, userID string, orgID string) (*UserOrg, error) {
	cols := organizationMemberSelectColumns()
	cols = append(cols, organizationSelectColumns()...)

	q := sq.Select(cols...).From("orgmember")
	q = q.Join("organization", "organization.id = orgmember.organization_id")
	q = q.Where(q.E("orgmember.user_id", userID))
	q = q.Where(q.E("organization.id", orgID))

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
			return nil, errors.Wrapf(err, "failed to fetch orgmember")
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

	out, err := mustSingleRow(userorgs)
	return out, errors.WithStack(err)
}

func (d *DB) GetUserOrgs(tx *sql.Tx, userID string, startOrgName string, limit int, sortDirection types.SortDirection) ([]*UserOrg, error) {
	cols := organizationMemberSelectColumns()
	cols = append(cols, organizationSelectColumns()...)

	q := sq.Select(cols...).From("orgmember")
	q = q.Where(q.E("orgmember.user_id", userID))
	q = q.Join("organization", "organization.id = orgmember.organization_id")
	q = q.OrderBy("organization.name")
	switch sortDirection {
	case types.SortDirectionAsc:
		q.Asc()
	case types.SortDirectionDesc:
		q.Desc()
	}

	if startOrgName != "" {
		switch sortDirection {
		case types.SortDirectionAsc:
			q = q.Where(q.G("organization.name", startOrgName))
		case types.SortDirectionDesc:
			q = q.Where(q.L("organization.name", startOrgName))
		}
	}

	if limit > 0 {
		q = q.Limit(limit)
	}

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
			return nil, errors.Wrapf(err, "failed to fetch orgmember")
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

func (d *DB) GetProjectGroupSubgroups(tx *sql.Tx, parentID string) ([]*types.ProjectGroup, error) {
	q := projectGroupSelect()
	q.Where(q.E("parent_id", parentID))
	projectGroups, _, err := d.fetchProjectGroups(tx, q)

	return projectGroups, errors.WithStack(err)
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

func (d *DB) DeleteOrgInvitationsByOrgID(tx *sql.Tx, orgID string) error {
	q := sq.NewDeleteBuilder()
	q.DeleteFrom("orginvitation").Where(q.E("organization_id", orgID))
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrap(err, "failed to delete orginvitation")
	}

	return nil
}

func (d *DB) DeleteOrgInvitationsByUserID(tx *sql.Tx, userID string) error {
	q := sq.NewDeleteBuilder()
	q.DeleteFrom("orginvitation").Where(q.E("user_id", userID))
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrap(err, "failed to delete orginvitation")
	}

	return nil
}
