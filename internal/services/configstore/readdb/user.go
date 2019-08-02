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
	userSelect = sb.Select("user.id", "user.data").From("user")
	userInsert = sb.Insert("user").Columns("id", "name", "data")

	//linkedaccountSelect     = sb.Select("id", "data").From("linkedaccount")
	//linkedaccountInsert     = sb.Insert("linkedaccount").Columns("id", "name", "data")
	linkedaccountuserInsert = sb.Insert("linkedaccount_user").Columns("id", "remotesourceid", "userid", "remoteuserid")
	//linkedaccountuserSelect    = sb.Select("id", "userid").From("linkedaccount_user")
	//linkedaccountprojectInsert = sb.Insert("linkedaccount_project").Columns("id", "userid")

	//usertokenSelect = sb.Select("tokenvalue", "userid").From("user_token")
	usertokenInsert = sb.Insert("user_token").Columns("tokenvalue", "userid")
)

func (r *ReadDB) insertUser(tx *db.Tx, data []byte) error {
	user := types.User{}
	if err := json.Unmarshal(data, &user); err != nil {
		return errors.Errorf("failed to unmarshal user: %w", err)
	}
	r.log.Debugf("inserting user: %s", util.Dump(user))
	// poor man insert or update...
	if err := r.deleteUser(tx, user.ID); err != nil {
		return err
	}
	q, args, err := userInsert.Values(user.ID, user.Name, data).ToSql()
	if err != nil {
		return errors.Errorf("failed to build query: %w", err)
	}
	if _, err := tx.Exec(q, args...); err != nil {
		return errors.Errorf("failed to insert user: %w", err)
	}

	// insert linkedaccounts_user
	for _, la := range user.LinkedAccounts {
		if err := r.deleteUserLinkedAccount(tx, la.ID); err != nil {
			return err
		}
		q, args, err = linkedaccountuserInsert.Values(la.ID, la.RemoteSourceID, user.ID, la.RemoteUserID).ToSql()
		if err != nil {
			return errors.Errorf("failed to build query: %w", err)
		}
		if _, err := tx.Exec(q, args...); err != nil {
			return errors.Errorf("failed to insert user: %w", err)
		}
	}
	// insert user_token
	for _, tokenValue := range user.Tokens {
		r.log.Debugf("inserting user token: %s", tokenValue)
		if err := r.deleteUserToken(tx, tokenValue); err != nil {
			return err
		}
		q, args, err = usertokenInsert.Values(tokenValue, user.ID).ToSql()
		if err != nil {
			return errors.Errorf("failed to build query: %w", err)
		}
		if _, err := tx.Exec(q, args...); err != nil {
			return errors.Errorf("failed to insert user: %w", err)
		}
	}

	return nil
}

func (r *ReadDB) deleteUser(tx *db.Tx, userID string) error {
	// delete user linked accounts
	if err := r.deleteUserLinkedAccounts(tx, userID); err != nil {
		return errors.Errorf("failed to delete user linked accounts: %w", err)
	}

	// delete user tokens
	if _, err := tx.Exec("delete from user_token where userid = $1", userID); err != nil {
		return errors.Errorf("failed to delete usertokens: %w", err)
	}

	// poor man insert or update...
	if _, err := tx.Exec("delete from user where id = $1", userID); err != nil {
		return errors.Errorf("failed to delete user: %w", err)
	}

	return nil
}

func (r *ReadDB) deleteUserLinkedAccounts(tx *db.Tx, userID string) error {
	// poor man insert or update...
	if _, err := tx.Exec("delete from linkedaccount_user where userid = $1", userID); err != nil {
		return errors.Errorf("failed to delete linked account: %w", err)
	}
	if _, err := tx.Exec("delete from linkedaccount_project where id = $1", userID); err != nil {
		return errors.Errorf("failed to delete linked account: %w", err)
	}
	return nil
}

func (r *ReadDB) deleteUserLinkedAccount(tx *db.Tx, id string) error {
	// poor man insert or update...
	if _, err := tx.Exec("delete from linkedaccount_user where id = $1", id); err != nil {
		return errors.Errorf("failed to delete linked account: %w", err)
	}
	if _, err := tx.Exec("delete from linkedaccount_project where id = $1", id); err != nil {
		return errors.Errorf("failed to delete linked account: %w", err)
	}
	return nil
}

func (r *ReadDB) deleteUserToken(tx *db.Tx, tokenValue string) error {
	// poor man insert or update...
	if _, err := tx.Exec("delete from user_token where tokenvalue = $1", tokenValue); err != nil {
		return errors.Errorf("failed to delete user_token: %w", err)
	}
	return nil
}

func (r *ReadDB) GetUser(tx *db.Tx, userRef string) (*types.User, error) {
	refType, err := common.ParseNameRef(userRef)
	if err != nil {
		return nil, err
	}

	var user *types.User
	switch refType {
	case common.RefTypeID:
		user, err = r.GetUserByID(tx, userRef)
	case common.RefTypeName:
		user, err = r.GetUserByName(tx, userRef)
	}
	return user, err
}

func (r *ReadDB) GetUserByID(tx *db.Tx, userID string) (*types.User, error) {
	q, args, err := userSelect.Where(sq.Eq{"id": userID}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	users, _, err := fetchUsers(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(users) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(users) == 0 {
		return nil, nil
	}
	return users[0], nil
}

func (r *ReadDB) GetUserByName(tx *db.Tx, name string) (*types.User, error) {
	q, args, err := userSelect.Where(sq.Eq{"name": name}).ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	users, _, err := fetchUsers(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(users) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(users) == 0 {
		return nil, nil
	}
	return users[0], nil
}

func (r *ReadDB) GetUserByTokenValue(tx *db.Tx, tokenValue string) (*types.User, error) {
	s := userSelect
	s = s.Join("user_token on user_token.userid = user.id")
	s = s.Where(sq.Eq{"user_token.tokenvalue": tokenValue})
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	users, _, err := fetchUsers(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(users) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(users) == 0 {
		return nil, nil
	}
	return users[0], nil
}

func (r *ReadDB) GetUserByLinkedAccount(tx *db.Tx, linkedAccountID string) (*types.User, error) {
	s := userSelect
	s = s.Join("linkedaccount_user as lau on lau.userid = user.id")
	s = s.Where(sq.Eq{"lau.id": linkedAccountID})
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	users, _, err := fetchUsers(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(users) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(users) == 0 {
		return nil, nil
	}
	return users[0], nil
}

func (r *ReadDB) GetUserByLinkedAccountRemoteUserIDandSource(tx *db.Tx, remoteUserID, remoteSourceID string) (*types.User, error) {
	s := userSelect
	s = s.Join("linkedaccount_user as lau on lau.userid = user.id")
	s = s.Where(sq.Eq{"lau.remoteuserid": remoteUserID, "lau.remotesourceid": remoteSourceID})
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	users, _, err := fetchUsers(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(users) > 1 {
		return nil, errors.Errorf("too many rows returned")
	}
	if len(users) == 0 {
		return nil, nil
	}
	return users[0], nil
}

func getUsersFilteredQuery(startUserName string, limit int, asc bool) sq.SelectBuilder {
	fields := []string{"id", "data"}

	s := sb.Select(fields...).From("user as user")
	if asc {
		s = s.OrderBy("user.name asc")
	} else {
		s = s.OrderBy("user.name desc")
	}
	if startUserName != "" {
		if asc {
			s = s.Where(sq.Gt{"user.name": startUserName})
		} else {
			s = s.Where(sq.Lt{"user.name": startUserName})
		}
	}
	if limit > 0 {
		s = s.Limit(uint64(limit))
	}

	return s
}

func (r *ReadDB) GetUsers(tx *db.Tx, startUserName string, limit int, asc bool) ([]*types.User, error) {
	var users []*types.User

	s := getUsersFilteredQuery(startUserName, limit, asc)
	q, args, err := s.ToSql()
	r.log.Debugf("q: %s, args: %s", q, util.Dump(args))
	if err != nil {
		return nil, errors.Errorf("failed to build query: %w", err)
	}

	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}

	users, _, err = scanUsers(rows)
	return users, err
}

func fetchUsers(tx *db.Tx, q string, args ...interface{}) ([]*types.User, []string, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	return scanUsers(rows)
}

func scanUser(rows *sql.Rows, additionalFields ...interface{}) (*types.User, string, error) {
	var id string
	var data []byte
	if err := rows.Scan(&id, &data); err != nil {
		return nil, "", errors.Errorf("failed to scan rows: %w", err)
	}
	user := types.User{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &user); err != nil {
			return nil, "", errors.Errorf("failed to unmarshal user: %w", err)
		}
	}

	return &user, id, nil
}

func scanUsers(rows *sql.Rows) ([]*types.User, []string, error) {
	users := []*types.User{}
	ids := []string{}
	for rows.Next() {
		p, id, err := scanUser(rows)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		users = append(users, p)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return users, ids, nil
}
