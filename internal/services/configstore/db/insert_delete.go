// Code generated by go generate; DO NOT EDIT.
package db

import (
	"encoding/json"
	"time"

	idb "agola.io/agola/internal/db"
	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/sql"
	"agola.io/agola/services/configstore/types"

	sq "github.com/Masterminds/squirrel"
)

func (d *DB) InsertOrUpdateRemoteSource(tx *sql.Tx, v *types.RemoteSource) error {
	var err error
	if v.Revision == 0 {
		err = d.InsertRemoteSource(tx, v)
	} else {
		err = d.UpdateRemoteSource(tx, v)
	}

	return errors.WithStack(err)
}

func (d *DB) InsertRemoteSource(tx *sql.Tx, v *types.RemoteSource) error {
	if v.Revision != 0 {
		return errors.Errorf("expected revision 0 got %d", v.Revision)
	}

	data, err := d.insertRemoteSourceData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.insertRemoteSourceQ(tx, v, data)
}

func (d *DB) insertRemoteSourceData(tx *sql.Tx, v *types.RemoteSource) ([]byte, error) {
	v.Revision = 1

	now := time.Now()
	v.SetCreationTime(now)
	v.SetUpdateTime(now)

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("remotesource").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert remotesource")
	}

	return data, nil
}

// insertRawRemoteSourceData should be used only for import.
// It won't update object times.
func (d *DB) insertRawRemoteSourceData(tx *sql.Tx, v *types.RemoteSource) ([]byte, error) {
	v.Revision = 1

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("remotesource").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert remotesource")
	}

	return data, nil
}

func (d *DB) UpdateRemoteSource(tx *sql.Tx, v *types.RemoteSource) error {
	data, err := d.updateRemoteSourceData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.updateRemoteSourceQ(tx, v, data)
}

func (d *DB) updateRemoteSourceData(tx *sql.Tx, v *types.RemoteSource) ([]byte, error) {
	if v.Revision < 1 {
		return nil, errors.Errorf("expected revision > 0 got %d", v.Revision)
	}

	curRevision := v.Revision
	v.Revision++

	v.SetUpdateTime(time.Now())

	data, err := json.Marshal(v)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q := sb.Update("remotesource").SetMap(map[string]interface{}{"id": v.ID, "revision": v.Revision, "data": data}).Where(sq.Eq{"id": v.ID, "revision": curRevision})
	res, err := d.exec(tx, q)
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update remotesource")
	}

	rows, err := res.RowsAffected()
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update remotesource")
	}

	if rows != 1 {
		v.Revision = curRevision
		return nil, idb.ErrConcurrent
	}

	return data, nil
}

func (d *DB) DeleteRemoteSource(tx *sql.Tx, id string) error {
	if err := d.deleteRemoteSourceData(tx, id); err != nil {
		return errors.WithStack(err)
	}

	return d.deleteRemoteSourceQ(tx, id)
}

func (d *DB) deleteRemoteSourceData(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from remotesource where id = $1", id); err != nil {
		return errors.Wrap(err, "failed to delete remotesource")
	}

	return nil
}

func (d *DB) InsertOrUpdateUser(tx *sql.Tx, v *types.User) error {
	var err error
	if v.Revision == 0 {
		err = d.InsertUser(tx, v)
	} else {
		err = d.UpdateUser(tx, v)
	}

	return errors.WithStack(err)
}

func (d *DB) InsertUser(tx *sql.Tx, v *types.User) error {
	if v.Revision != 0 {
		return errors.Errorf("expected revision 0 got %d", v.Revision)
	}

	data, err := d.insertUserData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.insertUserQ(tx, v, data)
}

func (d *DB) insertUserData(tx *sql.Tx, v *types.User) ([]byte, error) {
	v.Revision = 1

	now := time.Now()
	v.SetCreationTime(now)
	v.SetUpdateTime(now)

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("user_t").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert user_t")
	}

	return data, nil
}

// insertRawUserData should be used only for import.
// It won't update object times.
func (d *DB) insertRawUserData(tx *sql.Tx, v *types.User) ([]byte, error) {
	v.Revision = 1

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("user_t").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert user_t")
	}

	return data, nil
}

func (d *DB) UpdateUser(tx *sql.Tx, v *types.User) error {
	data, err := d.updateUserData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.updateUserQ(tx, v, data)
}

func (d *DB) updateUserData(tx *sql.Tx, v *types.User) ([]byte, error) {
	if v.Revision < 1 {
		return nil, errors.Errorf("expected revision > 0 got %d", v.Revision)
	}

	curRevision := v.Revision
	v.Revision++

	v.SetUpdateTime(time.Now())

	data, err := json.Marshal(v)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q := sb.Update("user_t").SetMap(map[string]interface{}{"id": v.ID, "revision": v.Revision, "data": data}).Where(sq.Eq{"id": v.ID, "revision": curRevision})
	res, err := d.exec(tx, q)
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update user_t")
	}

	rows, err := res.RowsAffected()
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update user_t")
	}

	if rows != 1 {
		v.Revision = curRevision
		return nil, idb.ErrConcurrent
	}

	return data, nil
}

func (d *DB) DeleteUser(tx *sql.Tx, id string) error {
	if err := d.deleteUserData(tx, id); err != nil {
		return errors.WithStack(err)
	}

	return d.deleteUserQ(tx, id)
}

func (d *DB) deleteUserData(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from user_t where id = $1", id); err != nil {
		return errors.Wrap(err, "failed to delete user_t")
	}

	return nil
}

func (d *DB) InsertOrUpdateUserToken(tx *sql.Tx, v *types.UserToken) error {
	var err error
	if v.Revision == 0 {
		err = d.InsertUserToken(tx, v)
	} else {
		err = d.UpdateUserToken(tx, v)
	}

	return errors.WithStack(err)
}

func (d *DB) InsertUserToken(tx *sql.Tx, v *types.UserToken) error {
	if v.Revision != 0 {
		return errors.Errorf("expected revision 0 got %d", v.Revision)
	}

	data, err := d.insertUserTokenData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.insertUserTokenQ(tx, v, data)
}

func (d *DB) insertUserTokenData(tx *sql.Tx, v *types.UserToken) ([]byte, error) {
	v.Revision = 1

	now := time.Now()
	v.SetCreationTime(now)
	v.SetUpdateTime(now)

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("usertoken").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert usertoken")
	}

	return data, nil
}

// insertRawUserTokenData should be used only for import.
// It won't update object times.
func (d *DB) insertRawUserTokenData(tx *sql.Tx, v *types.UserToken) ([]byte, error) {
	v.Revision = 1

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("usertoken").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert usertoken")
	}

	return data, nil
}

func (d *DB) UpdateUserToken(tx *sql.Tx, v *types.UserToken) error {
	data, err := d.updateUserTokenData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.updateUserTokenQ(tx, v, data)
}

func (d *DB) updateUserTokenData(tx *sql.Tx, v *types.UserToken) ([]byte, error) {
	if v.Revision < 1 {
		return nil, errors.Errorf("expected revision > 0 got %d", v.Revision)
	}

	curRevision := v.Revision
	v.Revision++

	v.SetUpdateTime(time.Now())

	data, err := json.Marshal(v)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q := sb.Update("usertoken").SetMap(map[string]interface{}{"id": v.ID, "revision": v.Revision, "data": data}).Where(sq.Eq{"id": v.ID, "revision": curRevision})
	res, err := d.exec(tx, q)
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update usertoken")
	}

	rows, err := res.RowsAffected()
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update usertoken")
	}

	if rows != 1 {
		v.Revision = curRevision
		return nil, idb.ErrConcurrent
	}

	return data, nil
}

func (d *DB) DeleteUserToken(tx *sql.Tx, id string) error {
	if err := d.deleteUserTokenData(tx, id); err != nil {
		return errors.WithStack(err)
	}

	return d.deleteUserTokenQ(tx, id)
}

func (d *DB) deleteUserTokenData(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from usertoken where id = $1", id); err != nil {
		return errors.Wrap(err, "failed to delete usertoken")
	}

	return nil
}

func (d *DB) InsertOrUpdateLinkedAccount(tx *sql.Tx, v *types.LinkedAccount) error {
	var err error
	if v.Revision == 0 {
		err = d.InsertLinkedAccount(tx, v)
	} else {
		err = d.UpdateLinkedAccount(tx, v)
	}

	return errors.WithStack(err)
}

func (d *DB) InsertLinkedAccount(tx *sql.Tx, v *types.LinkedAccount) error {
	if v.Revision != 0 {
		return errors.Errorf("expected revision 0 got %d", v.Revision)
	}

	data, err := d.insertLinkedAccountData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.insertLinkedAccountQ(tx, v, data)
}

func (d *DB) insertLinkedAccountData(tx *sql.Tx, v *types.LinkedAccount) ([]byte, error) {
	v.Revision = 1

	now := time.Now()
	v.SetCreationTime(now)
	v.SetUpdateTime(now)

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("linkedaccount").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert linkedaccount")
	}

	return data, nil
}

// insertRawLinkedAccountData should be used only for import.
// It won't update object times.
func (d *DB) insertRawLinkedAccountData(tx *sql.Tx, v *types.LinkedAccount) ([]byte, error) {
	v.Revision = 1

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("linkedaccount").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert linkedaccount")
	}

	return data, nil
}

func (d *DB) UpdateLinkedAccount(tx *sql.Tx, v *types.LinkedAccount) error {
	data, err := d.updateLinkedAccountData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.updateLinkedAccountQ(tx, v, data)
}

func (d *DB) updateLinkedAccountData(tx *sql.Tx, v *types.LinkedAccount) ([]byte, error) {
	if v.Revision < 1 {
		return nil, errors.Errorf("expected revision > 0 got %d", v.Revision)
	}

	curRevision := v.Revision
	v.Revision++

	v.SetUpdateTime(time.Now())

	data, err := json.Marshal(v)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q := sb.Update("linkedaccount").SetMap(map[string]interface{}{"id": v.ID, "revision": v.Revision, "data": data}).Where(sq.Eq{"id": v.ID, "revision": curRevision})
	res, err := d.exec(tx, q)
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update linkedaccount")
	}

	rows, err := res.RowsAffected()
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update linkedaccount")
	}

	if rows != 1 {
		v.Revision = curRevision
		return nil, idb.ErrConcurrent
	}

	return data, nil
}

func (d *DB) DeleteLinkedAccount(tx *sql.Tx, id string) error {
	if err := d.deleteLinkedAccountData(tx, id); err != nil {
		return errors.WithStack(err)
	}

	return d.deleteLinkedAccountQ(tx, id)
}

func (d *DB) deleteLinkedAccountData(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from linkedaccount where id = $1", id); err != nil {
		return errors.Wrap(err, "failed to delete linkedaccount")
	}

	return nil
}

func (d *DB) InsertOrUpdateOrganization(tx *sql.Tx, v *types.Organization) error {
	var err error
	if v.Revision == 0 {
		err = d.InsertOrganization(tx, v)
	} else {
		err = d.UpdateOrganization(tx, v)
	}

	return errors.WithStack(err)
}

func (d *DB) InsertOrganization(tx *sql.Tx, v *types.Organization) error {
	if v.Revision != 0 {
		return errors.Errorf("expected revision 0 got %d", v.Revision)
	}

	data, err := d.insertOrganizationData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.insertOrganizationQ(tx, v, data)
}

func (d *DB) insertOrganizationData(tx *sql.Tx, v *types.Organization) ([]byte, error) {
	v.Revision = 1

	now := time.Now()
	v.SetCreationTime(now)
	v.SetUpdateTime(now)

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("org").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert org")
	}

	return data, nil
}

// insertRawOrganizationData should be used only for import.
// It won't update object times.
func (d *DB) insertRawOrganizationData(tx *sql.Tx, v *types.Organization) ([]byte, error) {
	v.Revision = 1

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("org").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert org")
	}

	return data, nil
}

func (d *DB) UpdateOrganization(tx *sql.Tx, v *types.Organization) error {
	data, err := d.updateOrganizationData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.updateOrganizationQ(tx, v, data)
}

func (d *DB) updateOrganizationData(tx *sql.Tx, v *types.Organization) ([]byte, error) {
	if v.Revision < 1 {
		return nil, errors.Errorf("expected revision > 0 got %d", v.Revision)
	}

	curRevision := v.Revision
	v.Revision++

	v.SetUpdateTime(time.Now())

	data, err := json.Marshal(v)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q := sb.Update("org").SetMap(map[string]interface{}{"id": v.ID, "revision": v.Revision, "data": data}).Where(sq.Eq{"id": v.ID, "revision": curRevision})
	res, err := d.exec(tx, q)
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update org")
	}

	rows, err := res.RowsAffected()
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update org")
	}

	if rows != 1 {
		v.Revision = curRevision
		return nil, idb.ErrConcurrent
	}

	return data, nil
}

func (d *DB) DeleteOrganization(tx *sql.Tx, id string) error {
	if err := d.deleteOrganizationData(tx, id); err != nil {
		return errors.WithStack(err)
	}

	return d.deleteOrganizationQ(tx, id)
}

func (d *DB) deleteOrganizationData(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from org where id = $1", id); err != nil {
		return errors.Wrap(err, "failed to delete org")
	}

	return nil
}

func (d *DB) InsertOrUpdateOrganizationMember(tx *sql.Tx, v *types.OrganizationMember) error {
	var err error
	if v.Revision == 0 {
		err = d.InsertOrganizationMember(tx, v)
	} else {
		err = d.UpdateOrganizationMember(tx, v)
	}

	return errors.WithStack(err)
}

func (d *DB) InsertOrganizationMember(tx *sql.Tx, v *types.OrganizationMember) error {
	if v.Revision != 0 {
		return errors.Errorf("expected revision 0 got %d", v.Revision)
	}

	data, err := d.insertOrganizationMemberData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.insertOrganizationMemberQ(tx, v, data)
}

func (d *DB) insertOrganizationMemberData(tx *sql.Tx, v *types.OrganizationMember) ([]byte, error) {
	v.Revision = 1

	now := time.Now()
	v.SetCreationTime(now)
	v.SetUpdateTime(now)

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("orgmember").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert orgmember")
	}

	return data, nil
}

// insertRawOrganizationMemberData should be used only for import.
// It won't update object times.
func (d *DB) insertRawOrganizationMemberData(tx *sql.Tx, v *types.OrganizationMember) ([]byte, error) {
	v.Revision = 1

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("orgmember").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert orgmember")
	}

	return data, nil
}

func (d *DB) UpdateOrganizationMember(tx *sql.Tx, v *types.OrganizationMember) error {
	data, err := d.updateOrganizationMemberData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.updateOrganizationMemberQ(tx, v, data)
}

func (d *DB) updateOrganizationMemberData(tx *sql.Tx, v *types.OrganizationMember) ([]byte, error) {
	if v.Revision < 1 {
		return nil, errors.Errorf("expected revision > 0 got %d", v.Revision)
	}

	curRevision := v.Revision
	v.Revision++

	v.SetUpdateTime(time.Now())

	data, err := json.Marshal(v)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q := sb.Update("orgmember").SetMap(map[string]interface{}{"id": v.ID, "revision": v.Revision, "data": data}).Where(sq.Eq{"id": v.ID, "revision": curRevision})
	res, err := d.exec(tx, q)
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update orgmember")
	}

	rows, err := res.RowsAffected()
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update orgmember")
	}

	if rows != 1 {
		v.Revision = curRevision
		return nil, idb.ErrConcurrent
	}

	return data, nil
}

func (d *DB) DeleteOrganizationMember(tx *sql.Tx, id string) error {
	if err := d.deleteOrganizationMemberData(tx, id); err != nil {
		return errors.WithStack(err)
	}

	return d.deleteOrganizationMemberQ(tx, id)
}

func (d *DB) deleteOrganizationMemberData(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from orgmember where id = $1", id); err != nil {
		return errors.Wrap(err, "failed to delete orgmember")
	}

	return nil
}

func (d *DB) InsertOrUpdateProjectGroup(tx *sql.Tx, v *types.ProjectGroup) error {
	var err error
	if v.Revision == 0 {
		err = d.InsertProjectGroup(tx, v)
	} else {
		err = d.UpdateProjectGroup(tx, v)
	}

	return errors.WithStack(err)
}

func (d *DB) InsertProjectGroup(tx *sql.Tx, v *types.ProjectGroup) error {
	if v.Revision != 0 {
		return errors.Errorf("expected revision 0 got %d", v.Revision)
	}

	data, err := d.insertProjectGroupData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.insertProjectGroupQ(tx, v, data)
}

func (d *DB) insertProjectGroupData(tx *sql.Tx, v *types.ProjectGroup) ([]byte, error) {
	v.Revision = 1

	now := time.Now()
	v.SetCreationTime(now)
	v.SetUpdateTime(now)

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("projectgroup").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert projectgroup")
	}

	return data, nil
}

// insertRawProjectGroupData should be used only for import.
// It won't update object times.
func (d *DB) insertRawProjectGroupData(tx *sql.Tx, v *types.ProjectGroup) ([]byte, error) {
	v.Revision = 1

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("projectgroup").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert projectgroup")
	}

	return data, nil
}

func (d *DB) UpdateProjectGroup(tx *sql.Tx, v *types.ProjectGroup) error {
	data, err := d.updateProjectGroupData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.updateProjectGroupQ(tx, v, data)
}

func (d *DB) updateProjectGroupData(tx *sql.Tx, v *types.ProjectGroup) ([]byte, error) {
	if v.Revision < 1 {
		return nil, errors.Errorf("expected revision > 0 got %d", v.Revision)
	}

	curRevision := v.Revision
	v.Revision++

	v.SetUpdateTime(time.Now())

	data, err := json.Marshal(v)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q := sb.Update("projectgroup").SetMap(map[string]interface{}{"id": v.ID, "revision": v.Revision, "data": data}).Where(sq.Eq{"id": v.ID, "revision": curRevision})
	res, err := d.exec(tx, q)
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update projectgroup")
	}

	rows, err := res.RowsAffected()
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update projectgroup")
	}

	if rows != 1 {
		v.Revision = curRevision
		return nil, idb.ErrConcurrent
	}

	return data, nil
}

func (d *DB) DeleteProjectGroup(tx *sql.Tx, id string) error {
	if err := d.deleteProjectGroupData(tx, id); err != nil {
		return errors.WithStack(err)
	}

	return d.deleteProjectGroupQ(tx, id)
}

func (d *DB) deleteProjectGroupData(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from projectgroup where id = $1", id); err != nil {
		return errors.Wrap(err, "failed to delete projectgroup")
	}

	return nil
}

func (d *DB) InsertOrUpdateProject(tx *sql.Tx, v *types.Project) error {
	var err error
	if v.Revision == 0 {
		err = d.InsertProject(tx, v)
	} else {
		err = d.UpdateProject(tx, v)
	}

	return errors.WithStack(err)
}

func (d *DB) InsertProject(tx *sql.Tx, v *types.Project) error {
	if v.Revision != 0 {
		return errors.Errorf("expected revision 0 got %d", v.Revision)
	}

	data, err := d.insertProjectData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.insertProjectQ(tx, v, data)
}

func (d *DB) insertProjectData(tx *sql.Tx, v *types.Project) ([]byte, error) {
	v.Revision = 1

	now := time.Now()
	v.SetCreationTime(now)
	v.SetUpdateTime(now)

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("project").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert project")
	}

	return data, nil
}

// insertRawProjectData should be used only for import.
// It won't update object times.
func (d *DB) insertRawProjectData(tx *sql.Tx, v *types.Project) ([]byte, error) {
	v.Revision = 1

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("project").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert project")
	}

	return data, nil
}

func (d *DB) UpdateProject(tx *sql.Tx, v *types.Project) error {
	data, err := d.updateProjectData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.updateProjectQ(tx, v, data)
}

func (d *DB) updateProjectData(tx *sql.Tx, v *types.Project) ([]byte, error) {
	if v.Revision < 1 {
		return nil, errors.Errorf("expected revision > 0 got %d", v.Revision)
	}

	curRevision := v.Revision
	v.Revision++

	v.SetUpdateTime(time.Now())

	data, err := json.Marshal(v)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q := sb.Update("project").SetMap(map[string]interface{}{"id": v.ID, "revision": v.Revision, "data": data}).Where(sq.Eq{"id": v.ID, "revision": curRevision})
	res, err := d.exec(tx, q)
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update project")
	}

	rows, err := res.RowsAffected()
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update project")
	}

	if rows != 1 {
		v.Revision = curRevision
		return nil, idb.ErrConcurrent
	}

	return data, nil
}

func (d *DB) DeleteProject(tx *sql.Tx, id string) error {
	if err := d.deleteProjectData(tx, id); err != nil {
		return errors.WithStack(err)
	}

	return d.deleteProjectQ(tx, id)
}

func (d *DB) deleteProjectData(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from project where id = $1", id); err != nil {
		return errors.Wrap(err, "failed to delete project")
	}

	return nil
}

func (d *DB) InsertOrUpdateSecret(tx *sql.Tx, v *types.Secret) error {
	var err error
	if v.Revision == 0 {
		err = d.InsertSecret(tx, v)
	} else {
		err = d.UpdateSecret(tx, v)
	}

	return errors.WithStack(err)
}

func (d *DB) InsertSecret(tx *sql.Tx, v *types.Secret) error {
	if v.Revision != 0 {
		return errors.Errorf("expected revision 0 got %d", v.Revision)
	}

	data, err := d.insertSecretData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.insertSecretQ(tx, v, data)
}

func (d *DB) insertSecretData(tx *sql.Tx, v *types.Secret) ([]byte, error) {
	v.Revision = 1

	now := time.Now()
	v.SetCreationTime(now)
	v.SetUpdateTime(now)

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("secret").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert secret")
	}

	return data, nil
}

// insertRawSecretData should be used only for import.
// It won't update object times.
func (d *DB) insertRawSecretData(tx *sql.Tx, v *types.Secret) ([]byte, error) {
	v.Revision = 1

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("secret").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert secret")
	}

	return data, nil
}

func (d *DB) UpdateSecret(tx *sql.Tx, v *types.Secret) error {
	data, err := d.updateSecretData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.updateSecretQ(tx, v, data)
}

func (d *DB) updateSecretData(tx *sql.Tx, v *types.Secret) ([]byte, error) {
	if v.Revision < 1 {
		return nil, errors.Errorf("expected revision > 0 got %d", v.Revision)
	}

	curRevision := v.Revision
	v.Revision++

	v.SetUpdateTime(time.Now())

	data, err := json.Marshal(v)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q := sb.Update("secret").SetMap(map[string]interface{}{"id": v.ID, "revision": v.Revision, "data": data}).Where(sq.Eq{"id": v.ID, "revision": curRevision})
	res, err := d.exec(tx, q)
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update secret")
	}

	rows, err := res.RowsAffected()
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update secret")
	}

	if rows != 1 {
		v.Revision = curRevision
		return nil, idb.ErrConcurrent
	}

	return data, nil
}

func (d *DB) DeleteSecret(tx *sql.Tx, id string) error {
	if err := d.deleteSecretData(tx, id); err != nil {
		return errors.WithStack(err)
	}

	return d.deleteSecretQ(tx, id)
}

func (d *DB) deleteSecretData(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from secret where id = $1", id); err != nil {
		return errors.Wrap(err, "failed to delete secret")
	}

	return nil
}

func (d *DB) InsertOrUpdateVariable(tx *sql.Tx, v *types.Variable) error {
	var err error
	if v.Revision == 0 {
		err = d.InsertVariable(tx, v)
	} else {
		err = d.UpdateVariable(tx, v)
	}

	return errors.WithStack(err)
}

func (d *DB) InsertVariable(tx *sql.Tx, v *types.Variable) error {
	if v.Revision != 0 {
		return errors.Errorf("expected revision 0 got %d", v.Revision)
	}

	data, err := d.insertVariableData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.insertVariableQ(tx, v, data)
}

func (d *DB) insertVariableData(tx *sql.Tx, v *types.Variable) ([]byte, error) {
	v.Revision = 1

	now := time.Now()
	v.SetCreationTime(now)
	v.SetUpdateTime(now)

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("variable").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert variable")
	}

	return data, nil
}

// insertRawVariableData should be used only for import.
// It won't update object times.
func (d *DB) insertRawVariableData(tx *sql.Tx, v *types.Variable) ([]byte, error) {
	v.Revision = 1

	data, err := json.Marshal(v)
	if err != nil {
		v.Revision = 0
		return nil, errors.WithStack(err)
	}

	q := sb.Insert("variable").Columns("id", "revision", "data").Values(v.ID, v.Revision, data)
	if _, err := d.exec(tx, q); err != nil {
		v.Revision = 0
		return nil, errors.Wrap(err, "failed to insert variable")
	}

	return data, nil
}

func (d *DB) UpdateVariable(tx *sql.Tx, v *types.Variable) error {
	data, err := d.updateVariableData(tx, v)
	if err != nil {
		return errors.WithStack(err)
	}

	return d.updateVariableQ(tx, v, data)
}

func (d *DB) updateVariableData(tx *sql.Tx, v *types.Variable) ([]byte, error) {
	if v.Revision < 1 {
		return nil, errors.Errorf("expected revision > 0 got %d", v.Revision)
	}

	curRevision := v.Revision
	v.Revision++

	v.SetUpdateTime(time.Now())

	data, err := json.Marshal(v)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	q := sb.Update("variable").SetMap(map[string]interface{}{"id": v.ID, "revision": v.Revision, "data": data}).Where(sq.Eq{"id": v.ID, "revision": curRevision})
	res, err := d.exec(tx, q)
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update variable")
	}

	rows, err := res.RowsAffected()
	if err != nil {
		v.Revision = curRevision
		return nil, errors.Wrap(err, "failed to update variable")
	}

	if rows != 1 {
		v.Revision = curRevision
		return nil, idb.ErrConcurrent
	}

	return data, nil
}

func (d *DB) DeleteVariable(tx *sql.Tx, id string) error {
	if err := d.deleteVariableData(tx, id); err != nil {
		return errors.WithStack(err)
	}

	return d.deleteVariableQ(tx, id)
}

func (d *DB) deleteVariableData(tx *sql.Tx, id string) error {
	if _, err := tx.Exec("delete from variable where id = $1", id); err != nil {
		return errors.Wrap(err, "failed to delete variable")
	}

	return nil
}
