package db

import (
	"context"
	stdsql "database/sql"
	"encoding/json"
	"path"
	"strings"

	idb "agola.io/agola/internal/db"
	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/services/configstore/common"
	"agola.io/agola/internal/services/configstore/db/objects"
	"agola.io/agola/internal/sql"
	"agola.io/agola/services/configstore/types"
	stypes "agola.io/agola/services/types"

	sq "github.com/Masterminds/squirrel"
	"github.com/rs/zerolog"
)

//go:generate ../../../../tools/bin/generators -component configstore

const (
	dataTablesVersion  = 1
	queryTablesVersion = 1
)

var dstmts = []string{
	// data tables containing object. One table per object type to make things simple.
	"create table if not exists remotesource (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists user_t (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists usertoken (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists linkedaccount (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists org (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists orgmember (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists projectgroup (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists project (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists secret (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
	"create table if not exists variable (id varchar, revision bigint, data bytea, PRIMARY KEY (id))",
}

var qstmts = []string{
	// query tables for single object types. Can be rebuilt by data tables.
	"create table if not exists remotesource_q (id varchar, revision bigint, name varchar, data bytea, PRIMARY KEY (id))",
	"create table if not exists user_t_q (id varchar, revision bigint, name varchar, data bytea, PRIMARY KEY (id))",
	"create table if not exists usertoken_q (id varchar, revision bigint, user_id varchar, name varchar, value varchar, data bytea, PRIMARY KEY (id))",
	"create table if not exists linkedaccount_q (id varchar, revision bigint, remotesource_id varchar, user_id varchar, remoteuser_id varchar, data bytea, PRIMARY KEY (id))",
	"create table if not exists org_q (id varchar, revision bigint, name varchar, data bytea, PRIMARY KEY (id))",
	"create table if not exists orgmember_q (id varchar, revision bigint, org_id varchar, user_id varchar, data bytea, PRIMARY KEY (id))",
	"create table if not exists projectgroup_q (id varchar, revision bigint, name varchar, parent_id varchar, parent_kind varchar, data bytea, PRIMARY KEY (id))",
	"create table if not exists project_q (id varchar, revision bigint, name varchar, parent_id varchar, parent_kind varchar, data bytea, PRIMARY KEY (id))",
	"create table if not exists secret_q (id varchar, revision bigint, name varchar, parent_id varchar, parent_kind varchar, data bytea, PRIMARY KEY (id))",
	"create table if not exists variable_q (id varchar, revision bigint, name varchar, parent_id varchar, parent_kind varchar, data bytea, PRIMARY KEY (id))",
}

// denormalized tables for querying, can be rebuilt by query tables.
// TODO(sgotti) currently not needed

var sb = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

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

func (d *DB) Do(ctx context.Context, f func(tx *sql.Tx) error) error {
	return errors.WithStack(d.sdb.Do(ctx, f))
}

func (d *DB) Exec(tx *sql.Tx, rq sq.Sqlizer) (stdsql.Result, error) {
	return d.exec(tx, rq)
}

func (d *DB) Query(tx *sql.Tx, rq sq.Sqlizer) (*stdsql.Rows, error) {
	return d.query(tx, rq)
}

func (d *DB) DataTablesVersion() uint  { return dataTablesVersion }
func (d *DB) QueryTablesVersion() uint { return queryTablesVersion }

func (d *DB) DTablesStatements() []string {
	return dstmts
}

func (d *DB) QTablesStatements() []string {
	return qstmts
}

func (d *DB) ObjectsInfo() []idb.ObjectInfo {
	return objects.ObjectsInfo
}

func (d *DB) exec(tx *sql.Tx, rq sq.Sqlizer) (stdsql.Result, error) {
	q, args, err := rq.ToSql()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to build query")
	}
	// d.log.Debug().Msgf("q: %s, args: %s", q, util.Dump(args))

	r, err := tx.Exec(q, args...)
	return r, errors.WithStack(err)
}

func (d *DB) query(tx *sql.Tx, rq sq.Sqlizer) (*stdsql.Rows, error) {
	q, args, err := rq.ToSql()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to build query")
	}
	// d.log.Debug().Msgf("q: %s, args: %s", q, util.Dump(args))

	r, err := tx.Query(q, args...)
	return r, errors.WithStack(err)
}

func (d *DB) UnmarshalObject(data []byte) (stypes.Object, error) {
	var om stypes.TypeMeta
	if err := json.Unmarshal(data, &om); err != nil {
		return nil, errors.WithStack(err)
	}

	var obj stypes.Object

	switch om.Kind {
	case types.RemoteSourceKind:
		obj = &types.RemoteSource{}
	case types.UserKind:
		obj = &types.User{}
	case types.UserTokenKind:
		obj = &types.UserToken{}
	case types.LinkedAccountKind:
		obj = &types.LinkedAccount{}
	case types.OrganizationKind:
		obj = &types.Organization{}
	case types.OrganizationMemberKind:
		obj = &types.OrganizationMember{}
	case types.ProjectGroupKind:
		obj = &types.ProjectGroup{}
	case types.ProjectKind:
		obj = &types.Project{}
	case types.SecretKind:
		obj = &types.Secret{}
	case types.VariableKind:
		obj = &types.Variable{}
	default:
		panic(errors.Errorf("unknown object kind %q", om.Kind))
	}

	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, errors.WithStack(err)
	}

	return obj, nil
}
func (d *DB) InsertRawObject(tx *sql.Tx, obj stypes.Object) ([]byte, error) {
	switch obj.GetKind() {
	case types.RemoteSourceKind:
		return d.insertRawRemoteSourceData(tx, obj.(*types.RemoteSource))
	case types.UserKind:
		return d.insertRawUserData(tx, obj.(*types.User))
	case types.UserTokenKind:
		return d.insertRawUserTokenData(tx, obj.(*types.UserToken))
	case types.LinkedAccountKind:
		return d.insertRawLinkedAccountData(tx, obj.(*types.LinkedAccount))
	case types.OrganizationKind:
		return d.insertRawOrganizationData(tx, obj.(*types.Organization))
	case types.OrganizationMemberKind:
		return d.insertRawOrganizationMemberData(tx, obj.(*types.OrganizationMember))
	case types.ProjectGroupKind:
		return d.insertRawProjectGroupData(tx, obj.(*types.ProjectGroup))
	case types.ProjectKind:
		return d.insertRawProjectData(tx, obj.(*types.Project))
	case types.SecretKind:
		return d.insertRawSecretData(tx, obj.(*types.Secret))
	case types.VariableKind:
		return d.insertRawVariableData(tx, obj.(*types.Variable))
	default:
		panic(errors.Errorf("unknown object kind %q", obj.GetKind()))
	}
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
	q := remoteSourceQSelect.Where(sq.Eq{"id": remoteSourceID})
	remoteSources, _, err := d.fetchRemoteSources(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(remoteSources) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(remoteSources) == 0 {
		return nil, nil
	}
	return remoteSources[0], nil
}

func (d *DB) GetRemoteSourceByName(tx *sql.Tx, name string) (*types.RemoteSource, error) {
	q := remoteSourceQSelect.Where(sq.Eq{"name": name})
	remoteSources, _, err := d.fetchRemoteSources(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(remoteSources) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(remoteSources) == 0 {
		return nil, nil
	}
	return remoteSources[0], nil
}

func getRemoteSourcesFilteredQuery(startRemoteSourceName string, limit int, asc bool) sq.SelectBuilder {
	q := remoteSourceQSelect
	if asc {
		q = q.OrderBy("remotesource_q.name asc")
	} else {
		q = q.OrderBy("remotesource_q.name desc")
	}
	if startRemoteSourceName != "" {
		if asc {
			q = q.Where(sq.Gt{"remotesource_q.name": startRemoteSourceName})
		} else {
			q = q.Where(sq.Lt{"remotesource_q.name": startRemoteSourceName})
		}
	}
	if limit > 0 {
		q = q.Limit(uint64(limit))
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
	q := userQSelect.Where(sq.Eq{"id": userID})
	users, _, err := d.fetchUsers(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(users) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(users) == 0 {
		return nil, nil
	}
	return users[0], nil
}

func (d *DB) GetUserByName(tx *sql.Tx, name string) (*types.User, error) {
	q := userQSelect.Where(sq.Eq{"name": name})
	users, _, err := d.fetchUsers(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(users) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(users) == 0 {
		return nil, nil
	}
	return users[0], nil
}

func (d *DB) GetUserTokens(tx *sql.Tx, userID string) ([]*types.UserToken, error) {
	q := userTokenQSelect.Join("user_t_q on usertoken_q.user_id = user_t_q.id").Where(sq.Eq{"user_t_q.id": userID})
	tokens, _, err := d.fetchUserTokens(tx, q)

	return tokens, errors.WithStack(err)
}

func (d *DB) GetUserToken(tx *sql.Tx, userID, tokenName string) (*types.UserToken, error) {
	q := userTokenQSelect.Join("user_t_q on usertoken_q.user_id = user_t_q.id").Where(sq.Eq{"user_t_q.id": userID, "usertoken_q.name": tokenName})
	userTokens, _, err := d.fetchUserTokens(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(userTokens) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(userTokens) == 0 {
		return nil, nil
	}
	return userTokens[0], nil
}

func (d *DB) GetUserByTokenValue(tx *sql.Tx, tokenValue string) (*types.User, error) {
	q := userQSelect
	q = q.Join("usertoken_q on usertoken_q.user_id = user_t_q.id")
	q = q.Where(sq.Eq{"usertoken_q.value": tokenValue})

	users, _, err := d.fetchUsers(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(users) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(users) == 0 {
		return nil, nil
	}
	return users[0], nil
}

func (d *DB) GetLinkedAccounts(tx *sql.Tx, linkedAccountsIDs []string) ([]*types.LinkedAccount, error) {
	q := linkedAccountQSelect.Where(sq.Eq{"id": linkedAccountsIDs})
	linkedAccounts, _, err := d.fetchLinkedAccounts(tx, q)

	return linkedAccounts, errors.WithStack(err)
}

func (d *DB) GetLinkedAccount(tx *sql.Tx, linkedAccountID string) (*types.LinkedAccount, error) {
	q := linkedAccountQSelect.Where(sq.Eq{"id": linkedAccountID})
	linkedAccounts, _, err := d.fetchLinkedAccounts(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(linkedAccounts) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(linkedAccounts) == 0 {
		return nil, nil
	}
	return linkedAccounts[0], nil
}

// func (d *DB) GetLinkedAccount(tx *sql.Tx, userID, linkedAccountID string) (*types.LinkedAccount, error) {
// 	q := linkedAccountQSelect.Where(sq.Eq{"id": linkedAccountID, "user_id": userID})
// 	linkedAccounts, _, err := d.fetchLinkedAccounts(tx, q)
// 	if err != nil {
// 		return nil, errors.WithStack(err)
// 	}
// 	if len(linkedAccounts) > 1 {
// 		return nil, errors.Errorf("too many rows returned")
// 	}
// 	if len(linkedAccounts) == 0 {
// 		return nil, nil
// 	}
// 	return linkedAccounts[0], nil
// }

func (d *DB) GetUserLinkedAccounts(tx *sql.Tx, userID string) ([]*types.LinkedAccount, error) {
	q := linkedAccountQSelect.Join("user_t_q on linkedaccount_q.user_id = user_t_q.id").Where(sq.Eq{"user_t_q.id": userID})
	linkedAccounts, _, err := d.fetchLinkedAccounts(tx, q)

	return linkedAccounts, errors.WithStack(err)
}

func (d *DB) GetUserByLinkedAccount(tx *sql.Tx, linkedAccountID string) (*types.User, error) {
	q := userQSelect
	q = q.Join("linkedaccount_q on linkedaccount_q.user_id = user_t_q.id")
	q = q.Where(sq.Eq{"linkedaccount_q.id": linkedAccountID})
	users, _, err := d.fetchUsers(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(users) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(users) == 0 {
		return nil, nil
	}
	return users[0], nil
}

func (d *DB) GetLinkedAccountByRemoteUserIDandSource(tx *sql.Tx, remoteUserID, remoteSourceID string) (*types.LinkedAccount, error) {
	q := linkedAccountQSelect.Where(sq.Eq{"linkedaccount_q.remoteuser_id": remoteUserID, "linkedaccount_q.remotesource_id": remoteSourceID})
	linkedAccounts, _, err := d.fetchLinkedAccounts(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(linkedAccounts) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(linkedAccounts) == 0 {
		return nil, nil
	}
	return linkedAccounts[0], nil
}

// func (d *DB) GetUserByLinkedAccountRemoteUserIDandSource(tx *sql.Tx, remoteUserID, remoteSourceID string) (*types.User, error) {
// 	q := userQSelect
// 	q = q.Join("linkedaccount_q on linkedaccount_q.user_id = user_t_q.id")
// 	q = q.Where(sq.Eq{"linkedaccount_q.remoteuser_id": remoteUserID, "linkedaccount_q.remotesource_id": remoteSourceID})
// 	users, _, err := d.fetchUsers(tx, q)
// 	if err != nil {
// 		return nil, errors.WithStack(err)
// 	}
// 	if len(users) > 1 {
// 		return nil, errors.Errorf("too many rows returned")
// 	}
// 	if len(users) == 0 {
// 		return nil, nil
// 	}
// 	return users[0], nil
// }

func getUsersFilteredQuery(startUserName string, limit int, asc bool) sq.SelectBuilder {
	q := userQSelect
	if asc {
		q = q.OrderBy("user_t_q.name asc")
	} else {
		q = q.OrderBy("user_t_q.name desc")
	}
	if startUserName != "" {
		if asc {
			q = q.Where(sq.Gt{"user_t_q.name": startUserName})
		} else {
			q = q.Where(sq.Lt{"user_t_q.name": startUserName})
		}
	}
	if limit > 0 {
		q = q.Limit(uint64(limit))
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
	q := orgQSelect.Where(sq.Eq{"id": orgID})
	orgs, _, err := d.fetchOrganizations(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(orgs) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(orgs) == 0 {
		return nil, nil
	}

	return orgs[0], nil
}

func (d *DB) GetOrgByName(tx *sql.Tx, name string) (*types.Organization, error) {
	q := orgQSelect.Where(sq.Eq{"name": name})
	orgs, _, err := d.fetchOrganizations(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
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
	q := orgQSelect
	if asc {
		q = q.OrderBy("name asc")
	} else {
		q = q.OrderBy("name desc")
	}
	if startOrgName != "" {
		if asc {
			q = q.Where(sq.Gt{"name": startOrgName})
		} else {
			q = q.Where(sq.Lt{"name": startOrgName})
		}
	}
	if limit > 0 {
		q = q.Limit(uint64(limit))
	}

	return q
}

func (d *DB) GetOrgs(tx *sql.Tx, startOrgName string, limit int, asc bool) ([]*types.Organization, error) {
	q := getOrgsFilteredQuery(startOrgName, limit, asc)
	orgs, _, err := d.fetchOrganizations(tx, q)

	return orgs, errors.WithStack(err)
}

func (d *DB) GetOrgMemberByOrgUserID(tx *sql.Tx, orgID, userID string) (*types.OrganizationMember, error) {
	q := orgmemberQSelect.Where(sq.Eq{"orgmember_q.org_id": orgID, "orgmember_q.user_id": userID})

	oms, _, err := d.fetchOrganizationMembers(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(oms) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(oms) == 0 {
		return nil, nil
	}
	return oms[0], nil
}

type OrgUser struct {
	User *types.User
	Role types.MemberRole
}

// TODO(sgotti) implement cursor fetching
func (d *DB) GetOrgUsers(tx *sql.Tx, orgID string) ([]*OrgUser, error) {
	q := sb.Select(
		"orgmember_q.revision", "orgmember_q.data",
		"user_t_q.revision", "user_t_q.data").From("orgmember_q")
	q = q.Where(sq.Eq{"orgmember_q.org_id": orgID})
	q = q.Join("user_t_q on user_t_q.id = orgmember_q.user_id")
	q = q.OrderBy("user_t_q.name")

	rows, err := d.query(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer rows.Close()

	orgusers := []*OrgUser{}
	for rows.Next() {
		var orgmemberRevision uint64
		var orgmember *types.OrganizationMember
		var userRevision uint64
		var user *types.User
		var orgmemberdata []byte
		var userdata []byte
		if err := rows.Scan(&orgmemberRevision, &orgmemberdata, &userRevision, &userdata); err != nil {
			return nil, errors.Wrapf(err, "failed to scan rows")
		}

		if err := json.Unmarshal(orgmemberdata, &orgmember); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal orgmember")
		}
		orgmember.Revision = orgmemberRevision

		if err := json.Unmarshal(userdata, &user); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal org")
		}
		user.Revision = userRevision

		orgusers = append(orgusers, &OrgUser{
			User: user,
			Role: orgmember.MemberRole,
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
	q := sb.Select(
		"orgmember_q.revision", "orgmember_q.data",
		"org_q.revision", "org_q.data").From("orgmember_q")
	q = q.Where(sq.Eq{"orgmember_q.user_id": userID})
	q = q.Join("org_q on org_q.id = orgmember_q.org_id")
	q = q.OrderBy("org_q.name")

	rows, err := d.query(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer rows.Close()

	userorgs := []*UserOrg{}
	for rows.Next() {
		var orgmemberRevision uint64
		var orgmember *types.OrganizationMember
		var orgRevision uint64
		var org *types.Organization
		var orgmemberdata []byte
		var orgdata []byte
		if err := rows.Scan(&orgmemberRevision, &orgmemberdata, &orgRevision, &orgdata); err != nil {
			return nil, errors.Wrapf(err, "failed to scan rows")
		}
		if err := json.Unmarshal(orgmemberdata, &orgmember); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal orgmember")
		}
		orgmember.Revision = orgmemberRevision

		if err := json.Unmarshal(orgdata, &org); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal org")
		}
		org.Revision = orgRevision

		userorgs = append(userorgs, &UserOrg{
			Organization: org,
			Role:         orgmember.MemberRole,
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
	q := projectGroupQSelect.Where(sq.Eq{"id": projectGroupID})
	projectGroups, _, err := d.fetchProjectGroups(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(projectGroups) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(projectGroups) == 0 {
		return nil, nil
	}
	return projectGroups[0], nil
}

func (d *DB) GetProjectGroupByName(tx *sql.Tx, parentID, name string) (*types.ProjectGroup, error) {
	q := projectGroupQSelect.Where(sq.Eq{"parent_id": parentID, "name": name})
	projectGroups, _, err := d.fetchProjectGroups(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(projectGroups) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(projectGroups) == 0 {
		return nil, nil
	}
	return projectGroups[0], nil
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
	q := projectGroupQSelect.Where(sq.Eq{"parent_id": parentID})
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
	q := projectQSelect.Where(sq.Eq{"id": projectID})

	projects, _, err := d.fetchProjects(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(projects) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(projects) == 0 {
		return nil, nil
	}
	return projects[0], nil
}

func (d *DB) GetProjectByName(tx *sql.Tx, parentID, name string) (*types.Project, error) {
	q := projectQSelect.Where(sq.Eq{"parent_id": parentID, "name": name})

	projects, _, err := d.fetchProjects(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(projects) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(projects) == 0 {
		return nil, nil
	}
	return projects[0], nil
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
	q := projectQSelect.Where(sq.Eq{"parent_id": parentID})
	projects, _, err := d.fetchProjects(tx, q)

	return projects, errors.WithStack(err)
}

func (d *DB) GetSecretByID(tx *sql.Tx, secretID string) (*types.Secret, error) {
	q := secretQSelect.Where(sq.Eq{"id": secretID})
	secrets, _, err := d.fetchSecrets(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(secrets) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(secrets) == 0 {
		return nil, nil
	}
	return secrets[0], nil
}

func (d *DB) GetSecretByName(tx *sql.Tx, parentID, name string) (*types.Secret, error) {
	q := secretQSelect.Where(sq.Eq{"parent_id": parentID, "name": name})
	secrets, _, err := d.fetchSecrets(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(secrets) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(secrets) == 0 {
		return nil, nil
	}
	return secrets[0], nil
}

func (d *DB) GetSecrets(tx *sql.Tx, parentID string) ([]*types.Secret, error) {
	q := secretQSelect.Where(sq.Eq{"parent_id": parentID})
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
	q := variableQSelect.Where(sq.Eq{"id": variableID})
	variables, _, err := d.fetchVariables(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(variables) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(variables) == 0 {
		return nil, nil
	}
	return variables[0], nil
}

func (d *DB) GetVariableByName(tx *sql.Tx, parentID, name string) (*types.Variable, error) {
	q := variableQSelect.Where(sq.Eq{"parent_id": parentID, "name": name})
	variables, _, err := d.fetchVariables(tx, q)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(variables) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(variables) == 0 {
		return nil, nil
	}
	return variables[0], nil
}

func (d *DB) GetVariables(tx *sql.Tx, parentID string) ([]*types.Variable, error) {
	q := variableQSelect.Where(sq.Eq{"parent_id": parentID})
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
	q := projectQSelect.OrderBy("id")
	projects, _, err := d.fetchProjects(tx, q)

	return projects, errors.WithStack(err)
}

func (d *DB) GetAllProjectGroups(tx *sql.Tx) ([]*types.ProjectGroup, error) {
	q := projectGroupQSelect.OrderBy("id")
	projectGroups, _, err := d.fetchProjectGroups(tx, q)

	return projectGroups, errors.WithStack(err)
}

func (d *DB) GetAllSecrets(tx *sql.Tx) ([]*types.Secret, error) {
	q := secretQSelect.OrderBy("id")
	secrets, _, err := d.fetchSecrets(tx, q)

	return secrets, errors.WithStack(err)
}

func (d *DB) GetAllVariables(tx *sql.Tx) ([]*types.Variable, error) {
	q := variableQSelect.OrderBy("id")
	variables, _, err := d.fetchVariables(tx, q)

	return variables, errors.WithStack(err)
}
