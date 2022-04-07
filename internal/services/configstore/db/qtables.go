package db

import (
	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/sql"
	"agola.io/agola/services/configstore/types"
	stypes "agola.io/agola/services/types"

	sq "github.com/Masterminds/squirrel"
)

var (
	// TODO(sgotti) generate also these ones
	// TODO(sgotti) currently we are duplicating revision and data in the query tables. Another solution will be to join with the data table (what about performances?)
	remoteSourceQSelect = sb.Select("remotesource_q.id", "remotesource_q.revision", "remotesource_q.data").From("remotesource_q")
	remoteSourceQInsert = func(id string, revision uint64, name string, data []byte) sq.InsertBuilder {
		return sb.Insert("remotesource_q").Columns("id", "revision", "name", "data").Values(id, revision, name, data)
	}
	remoteSourceQUpdate = func(id string, revision uint64, name string, data []byte) sq.UpdateBuilder {
		return sb.Update("remotesource_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "name": name, "data": data}).Where(sq.Eq{"id": id})
	}

	userQSelect = sb.Select("user_t_q.id", "user_t_q.revision", "user_t_q.data").From("user_t_q")
	userQInsert = func(id string, revision uint64, name string, data []byte) sq.InsertBuilder {
		return sb.Insert("user_t_q").Columns("id", "revision", "name", "data").Values(id, revision, name, data)
	}
	userQUpdate = func(id string, revision uint64, name string, data []byte) sq.UpdateBuilder {
		return sb.Update("user_t_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "name": name, "data": data}).Where(sq.Eq{"id": id})
	}

	userTokenQSelect = sb.Select("usertoken_q.id", "usertoken_q.revision", "usertoken_q.data").From("usertoken_q")
	userTokenQInsert = func(id string, revision uint64, userID, name, value string, data []byte) sq.InsertBuilder {
		return sb.Insert("usertoken_q").Columns("id", "revision", "user_id", "name", "value", "data").Values(id, revision, userID, name, value, data)
	}
	userTokenQUpdate = func(id string, revision uint64, userID, name, value string, data []byte) sq.UpdateBuilder {
		return sb.Update("usertoken_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "user_id": userID, "name": name, "value": value, "data": data}).Where(sq.Eq{"id": id})
	}

	linkedAccountQSelect = sb.Select("linkedaccount_q.id", "linkedaccount_q.revision", "linkedaccount_q.data").From("linkedaccount_q")
	linkedAccountQInsert = func(id string, revision uint64, userID, remoteSourceID, remoteUserID string, data []byte) sq.InsertBuilder {
		return sb.Insert("linkedaccount_q").Columns("id", "revision", "user_id", "remotesource_id", "remoteuser_id", "data").Values(id, revision, userID, remoteSourceID, remoteUserID, data)
	}
	linkedAccountQUpdate = func(id string, revision uint64, userID, remoteSourceID, remoteUserID string, data []byte) sq.UpdateBuilder {
		return sb.Update("linkedaccount_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "user_id": userID, "remotesource_id": remoteSourceID, "remoteuser_id": remoteUserID, "data": data}).Where(sq.Eq{"id": id})
	}

	orgQSelect = sb.Select("org_q.id", "org_q.revision", "org_q.data").From("org_q")
	orgQInsert = func(id string, revision uint64, name string, data []byte) sq.InsertBuilder {
		return sb.Insert("org_q").Columns("id", "revision", "name", "data").Values(id, revision, name, data)
	}
	orgQUpdate = func(id string, revision uint64, name string, data []byte) sq.UpdateBuilder {
		return sb.Update("org_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "name": name, "data": data}).Where(sq.Eq{"id": id})
	}

	orgmemberQSelect = sb.Select("orgmember_q.id", "orgmember_q.revision", "orgmember_q.data").From("orgmember_q")
	orgmemberQInsert = func(id string, revision uint64, orgID, userID string, data []byte) sq.InsertBuilder {
		return sb.Insert("orgmember_q").Columns("id", "revision", "org_id", "user_id", "data").Values(id, revision, orgID, userID, data)
	}
	orgmemberQUpdate = func(id string, revision uint64, orgID, userID string, data []byte) sq.UpdateBuilder {
		return sb.Update("orgmember_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "org_id": orgID, "user_id": userID, "data": data}).Where(sq.Eq{"id": id})
	}

	projectGroupQSelect = sb.Select("projectgroup_q.id", "projectgroup_q.revision", "projectgroup_q.data").From("projectgroup_q")
	projectGroupQInsert = func(id string, revision uint64, name, parentID string, parentKind types.ObjectKind, data []byte) sq.InsertBuilder {
		return sb.Insert("projectgroup_q").Columns("id", "revision", "name", "parent_id", "parent_kind", "data").Values(id, revision, name, parentID, parentKind, data)
	}
	projectGroupQUpdate = func(id string, revision uint64, name, parentID string, parentKind types.ObjectKind, data []byte) sq.UpdateBuilder {
		return sb.Update("projectgroup_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "name": name, "parent_id": parentID, "parent_kind": parentKind, "data": data}).Where(sq.Eq{"id": id})
	}

	projectQSelect = sb.Select("project_q.id", "project_q.revision", "project_q.data").From("project_q")
	projectQInsert = func(id string, revision uint64, name, parentID string, parentKind types.ObjectKind, data []byte) sq.InsertBuilder {
		return sb.Insert("project_q").Columns("id", "revision", "name", "parent_id", "parent_kind", "data").Values(id, revision, name, parentID, parentKind, data)
	}
	projectQUpdate = func(id string, revision uint64, name, parentID string, parentKind types.ObjectKind, data []byte) sq.UpdateBuilder {
		return sb.Update("project_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "name": name, "parent_id": parentID, "parent_kind": parentKind, "data": data}).Where(sq.Eq{"id": id})
	}

	secretQSelect = sb.Select("secret_q.id", "secret_q.revision", "secret_q.data").From("secret_q")
	secretQInsert = func(id string, revision uint64, name, parentID string, parentKind types.ObjectKind, data []byte) sq.InsertBuilder {
		return sb.Insert("secret_q").Columns("id", "revision", "name", "parent_id", "parent_kind", "data").Values(id, revision, name, parentID, parentKind, data)
	}
	secretQUpdate = func(id string, revision uint64, name, parentID string, parentKind types.ObjectKind, data []byte) sq.UpdateBuilder {
		return sb.Update("secret_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "name": name, "parent_id": parentID, "parent_kind": parentKind, "data": data}).Where(sq.Eq{"id": id})
	}

	variableQSelect = sb.Select("variable_q.id", "variable_q.revision", "variable_q.data").From("variable_q")
	variableQInsert = func(id string, revision uint64, name, parentID string, parentKind types.ObjectKind, data []byte) sq.InsertBuilder {
		return sb.Insert("variable_q").Columns("id", "revision", "name", "parent_id", "parent_kind", "data").Values(id, revision, name, parentID, parentKind, data)
	}
	variableQUpdate = func(id string, revision uint64, name, parentID string, parentKind types.ObjectKind, data []byte) sq.UpdateBuilder {
		return sb.Update("variable_q").SetMap(map[string]interface{}{"id": id, "revision": revision, "name": name, "parent_id": parentID, "parent_kind": parentKind, "data": data}).Where(sq.Eq{"id": id})
	}
)

func (d *DB) InsertObjectQ(tx *sql.Tx, obj stypes.Object, data []byte) error {
	switch obj.GetKind() {
	case types.RemoteSourceKind:
		return d.insertRemoteSourceQ(tx, obj.(*types.RemoteSource), data)
	case types.UserKind:
		return d.insertUserQ(tx, obj.(*types.User), data)
	case types.UserTokenKind:
		return d.insertUserTokenQ(tx, obj.(*types.UserToken), data)
	case types.LinkedAccountKind:
		return d.insertLinkedAccountQ(tx, obj.(*types.LinkedAccount), data)
	case types.OrganizationKind:
		return d.insertOrganizationQ(tx, obj.(*types.Organization), data)
	case types.OrganizationMemberKind:
		return d.insertOrganizationMemberQ(tx, obj.(*types.OrganizationMember), data)
	case types.ProjectGroupKind:
		return d.insertProjectGroupQ(tx, obj.(*types.ProjectGroup), data)
	case types.ProjectKind:
		return d.insertProjectQ(tx, obj.(*types.Project), data)
	case types.SecretKind:
		return d.insertSecretQ(tx, obj.(*types.Secret), data)
	case types.VariableKind:
		return d.insertVariableQ(tx, obj.(*types.Variable), data)

	default:
		panic(errors.Errorf("unknown object kind %q", obj.GetKind()))
	}
}

func (d *DB) insertRemoteSourceQ(tx *sql.Tx, remoteSource *types.RemoteSource, data []byte) error {
	q := remoteSourceQInsert(remoteSource.ID, remoteSource.Revision, remoteSource.Name, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert remotesource_q")
	}

	return nil
}

func (d *DB) updateRemoteSourceQ(tx *sql.Tx, remoteSource *types.RemoteSource, data []byte) error {
	q := remoteSourceQUpdate(remoteSource.ID, remoteSource.Revision, remoteSource.Name, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert remotesource_q")
	}

	return nil
}

func (d *DB) deleteRemoteSourceQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from remotesource_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete remotesource_q")
	}

	return nil
}

func (d *DB) insertUserQ(tx *sql.Tx, user *types.User, data []byte) error {
	q := userQInsert(user.ID, user.Revision, user.Name, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert user_q")
	}

	return nil
}

func (d *DB) updateUserQ(tx *sql.Tx, user *types.User, data []byte) error {
	q := userQUpdate(user.ID, user.Revision, user.Name, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert user_q")
	}

	return nil
}

func (d *DB) deleteUserQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from user_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete user_q")
	}

	return nil
}

func (d *DB) insertUserTokenQ(tx *sql.Tx, userToken *types.UserToken, data []byte) error {
	q := userTokenQInsert(userToken.ID, userToken.Revision, userToken.UserID, userToken.Name, userToken.Value, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert usertoken_q")
	}

	return nil
}

func (d *DB) updateUserTokenQ(tx *sql.Tx, userToken *types.UserToken, data []byte) error {
	q := userTokenQUpdate(userToken.ID, userToken.Revision, userToken.UserID, userToken.Name, userToken.Value, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert usertoken_q")
	}

	return nil
}

func (d *DB) deleteUserTokenQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from usertoken_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete usertoken_q")
	}

	return nil
}

func (d *DB) insertLinkedAccountQ(tx *sql.Tx, linkedAccount *types.LinkedAccount, data []byte) error {
	q := linkedAccountQInsert(linkedAccount.ID, linkedAccount.Revision, linkedAccount.UserID, linkedAccount.RemoteSourceID, linkedAccount.RemoteUserID, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert linkedaccount_q")
	}

	return nil
}

func (d *DB) updateLinkedAccountQ(tx *sql.Tx, linkedAccount *types.LinkedAccount, data []byte) error {
	q := linkedAccountQUpdate(linkedAccount.ID, linkedAccount.Revision, linkedAccount.UserID, linkedAccount.RemoteSourceID, linkedAccount.RemoteUserID, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert linkedaccount_q")
	}

	return nil
}

func (d *DB) deleteLinkedAccountQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from linkedaccount_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete linkedaccount_q")
	}

	return nil
}

func (d *DB) insertOrganizationQ(tx *sql.Tx, org *types.Organization, data []byte) error {
	q := orgQInsert(org.ID, org.Revision, org.Name, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert org_q")
	}

	return nil
}

func (d *DB) updateOrganizationQ(tx *sql.Tx, org *types.Organization, data []byte) error {
	q := orgQUpdate(org.ID, org.Revision, org.Name, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert org_q")
	}

	return nil
}

func (d *DB) deleteOrganizationQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from org_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete org_q")
	}

	return nil
}

func (d *DB) insertOrganizationMemberQ(tx *sql.Tx, orgmember *types.OrganizationMember, data []byte) error {
	q := orgmemberQInsert(orgmember.ID, orgmember.Revision, orgmember.OrganizationID, orgmember.UserID, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert orgmember_q")
	}

	return nil
}

func (d *DB) updateOrganizationMemberQ(tx *sql.Tx, orgmember *types.OrganizationMember, data []byte) error {
	q := orgmemberQUpdate(orgmember.ID, orgmember.Revision, orgmember.OrganizationID, orgmember.UserID, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert orgmember_q")
	}

	return nil
}

func (d *DB) deleteOrganizationMemberQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from orgmember_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete orgmember_q")
	}

	return nil
}

func (d *DB) insertProjectGroupQ(tx *sql.Tx, projectGroup *types.ProjectGroup, data []byte) error {
	q := projectGroupQInsert(projectGroup.ID, projectGroup.Revision, projectGroup.Name, projectGroup.Parent.ID, projectGroup.Parent.Kind, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert projectgroup_q")
	}

	return nil
}

func (d *DB) updateProjectGroupQ(tx *sql.Tx, projectGroup *types.ProjectGroup, data []byte) error {
	q := projectGroupQUpdate(projectGroup.ID, projectGroup.Revision, projectGroup.Name, projectGroup.Parent.ID, projectGroup.Parent.Kind, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert projectgroup_q")
	}

	return nil
}

func (d *DB) deleteProjectGroupQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from projectgroup_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete projectgroup_q")
	}

	return nil
}

func (d *DB) insertProjectQ(tx *sql.Tx, project *types.Project, data []byte) error {
	q := projectQInsert(project.ID, project.Revision, project.Name, project.Parent.ID, project.Parent.Kind, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert project_q")
	}

	return nil
}

func (d *DB) updateProjectQ(tx *sql.Tx, project *types.Project, data []byte) error {
	q := projectQUpdate(project.ID, project.Revision, project.Name, project.Parent.ID, project.Parent.Kind, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert project_q")
	}

	return nil
}

func (d *DB) deleteProjectQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from project_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete project_q")
	}

	return nil
}

func (d *DB) insertSecretQ(tx *sql.Tx, secret *types.Secret, data []byte) error {
	q := secretQInsert(secret.ID, secret.Revision, secret.Name, secret.Parent.ID, secret.Parent.Kind, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert secret_q")
	}

	return nil
}

func (d *DB) updateSecretQ(tx *sql.Tx, secret *types.Secret, data []byte) error {
	q := secretQUpdate(secret.ID, secret.Revision, secret.Name, secret.Parent.ID, secret.Parent.Kind, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert secret_q")
	}

	return nil
}

func (d *DB) deleteSecretQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from secret_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete secret_q")
	}

	return nil
}

func (d *DB) insertVariableQ(tx *sql.Tx, variable *types.Variable, data []byte) error {
	q := variableQInsert(variable.ID, variable.Revision, variable.Name, variable.Parent.ID, variable.Parent.Kind, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert variable_q")
	}

	return nil
}

func (d *DB) updateVariableQ(tx *sql.Tx, variable *types.Variable, data []byte) error {
	q := variableQUpdate(variable.ID, variable.Revision, variable.Name, variable.Parent.ID, variable.Parent.Kind, data)
	if _, err := d.exec(tx, q); err != nil {
		return errors.Wrapf(err, "failed to insert variable_q")
	}

	return nil
}

func (d *DB) deleteVariableQ(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from variable_q where id = $1", id); err != nil {
		return errors.Wrapf(err, "failed to delete variable_q")
	}

	return nil
}
