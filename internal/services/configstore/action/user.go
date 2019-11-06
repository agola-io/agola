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
	"encoding/json"
	"time"

	"agola.io/agola/internal/datamanager"
	"agola.io/agola/internal/db"
	"agola.io/agola/internal/services/configstore/readdb"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	uuid "github.com/satori/go.uuid"
	errors "golang.org/x/xerrors"
)

type CreateUserRequest struct {
	UserName string

	CreateUserLARequest *CreateUserLARequest
}

func (h *ActionHandler) CreateUser(ctx context.Context, req *CreateUserRequest) (*types.User, error) {
	if req.UserName == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("user name required"))
	}
	if !util.ValidateName(req.UserName) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid user name %q", req.UserName))
	}

	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the username (and in future the email) to ensure no
	// concurrent user creation/modification using the same name
	cgNames := []string{util.EncodeSha256Hex("username-" + req.UserName)}
	var rs *types.RemoteSource

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check duplicate user name
		u, err := h.readDB.GetUserByName(tx, req.UserName)
		if err != nil {
			return err
		}
		if u != nil {
			return util.NewErrBadRequest(errors.Errorf("user with name %q already exists", u.Name))
		}

		if req.CreateUserLARequest != nil {
			rs, err = h.readDB.GetRemoteSourceByName(tx, req.CreateUserLARequest.RemoteSourceName)
			if err != nil {
				return err
			}
			if rs == nil {
				return util.NewErrBadRequest(errors.Errorf("remote source %q doesn't exist", req.CreateUserLARequest.RemoteSourceName))
			}
			user, err := h.readDB.GetUserByLinkedAccountRemoteUserIDandSource(tx, req.CreateUserLARequest.RemoteUserID, rs.ID)
			if err != nil {
				return errors.Errorf("failed to get user for remote user id %q and remote source %q: %w", req.CreateUserLARequest.RemoteUserID, rs.ID, err)
			}
			if user != nil {
				return util.NewErrBadRequest(errors.Errorf("user for remote user id %q for remote source %q already exists", req.CreateUserLARequest.RemoteUserID, req.CreateUserLARequest.RemoteSourceName))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	user := &types.User{
		ID:     uuid.NewV4().String(),
		Name:   req.UserName,
		Secret: util.EncodeSha1Hex(uuid.NewV4().String()),
	}
	if req.CreateUserLARequest != nil {
		if user.LinkedAccounts == nil {
			user.LinkedAccounts = make(map[string]*types.LinkedAccount)
		}

		la := &types.LinkedAccount{
			ID:                         uuid.NewV4().String(),
			RemoteSourceID:             rs.ID,
			RemoteUserID:               req.CreateUserLARequest.RemoteUserID,
			RemoteUserName:             req.CreateUserLARequest.RemoteUserName,
			UserAccessToken:            req.CreateUserLARequest.UserAccessToken,
			Oauth2AccessToken:          req.CreateUserLARequest.Oauth2AccessToken,
			Oauth2RefreshToken:         req.CreateUserLARequest.Oauth2RefreshToken,
			Oauth2AccessTokenExpiresAt: req.CreateUserLARequest.Oauth2AccessTokenExpiresAt,
		}

		user.LinkedAccounts[la.ID] = la
	}

	userj, err := json.Marshal(user)
	if err != nil {
		return nil, errors.Errorf("failed to marshal user: %w", err)
	}

	// create root user project group
	pg := &types.ProjectGroup{
		ID: uuid.NewV4().String(),
		// use public visibility
		Visibility: types.VisibilityPublic,
		Parent: types.Parent{
			Type: types.ConfigTypeUser,
			ID:   user.ID,
		},
	}
	pgj, err := json.Marshal(pg)
	if err != nil {
		return nil, errors.Errorf("failed to marshal project group: %w", err)
	}

	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeUser),
			ID:         user.ID,
			Data:       userj,
		},
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeProjectGroup),
			ID:         pg.ID,
			Data:       pgj,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return user, err
}

func (h *ActionHandler) DeleteUser(ctx context.Context, userRef string) error {
	var user *types.User

	var cgt *datamanager.ChangeGroupsUpdateToken
	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error

		// check user existance
		user, err = h.readDB.GetUser(tx, userRef)
		if err != nil {
			return err
		}
		if user == nil {
			return util.NewErrBadRequest(errors.Errorf("user %q doesn't exist", userRef))
		}

		// changegroup is the userid
		cgNames := []string{util.EncodeSha256Hex("userid-" + user.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypeDelete,
			DataType:   string(types.ConfigTypeUser),
			ID:         user.ID,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return err
}

type UpdateUserRequest struct {
	UserRef string

	UserName string
}

func (h *ActionHandler) UpdateUser(ctx context.Context, req *UpdateUserRequest) (*types.User, error) {
	var cgt *datamanager.ChangeGroupsUpdateToken

	cgNames := []string{}
	var user *types.User

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		user, err = h.readDB.GetUser(tx, req.UserRef)
		if err != nil {
			return err
		}
		if user == nil {
			return util.NewErrBadRequest(errors.Errorf("user %q doesn't exist", req.UserRef))
		}

		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		if req.UserName != "" {
			// check duplicate user name
			u, err := h.readDB.GetUserByName(tx, req.UserName)
			if err != nil {
				return err
			}
			if u != nil {
				return util.NewErrBadRequest(errors.Errorf("user with name %q already exists", u.Name))
			}
			// changegroup is the username (and in future the email) to ensure no
			// concurrent user creation/modification using the same name
			cgNames = append(cgNames, util.EncodeSha256Hex("username-"+req.UserName))
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	if req.UserName != "" {
		user.Name = req.UserName
	}

	userj, err := json.Marshal(user)
	if err != nil {
		return nil, errors.Errorf("failed to marshal user: %w", err)
	}

	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeUser),
			ID:         user.ID,
			Data:       userj,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return user, err
}

type CreateUserLARequest struct {
	UserRef string

	RemoteSourceName           string
	RemoteUserID               string
	RemoteUserName             string
	UserAccessToken            string
	Oauth2AccessToken          string
	Oauth2RefreshToken         string
	Oauth2AccessTokenExpiresAt time.Time
}

func (h *ActionHandler) CreateUserLA(ctx context.Context, req *CreateUserLARequest) (*types.LinkedAccount, error) {
	if req.UserRef == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("user ref required"))
	}
	if req.RemoteSourceName == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("remote source name required"))
	}

	var user *types.User
	var rs *types.RemoteSource

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		user, err = h.readDB.GetUser(tx, req.UserRef)
		if err != nil {
			return err
		}
		if user == nil {
			return util.NewErrBadRequest(errors.Errorf("user %q doesn't exist", req.UserRef))
		}

		// changegroup is the userid
		cgNames := []string{util.EncodeSha256Hex("userid-" + user.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		rs, err = h.readDB.GetRemoteSourceByName(tx, req.RemoteSourceName)
		if err != nil {
			return err
		}
		if rs == nil {
			return util.NewErrBadRequest(errors.Errorf("remote source %q doesn't exist", req.RemoteSourceName))
		}

		user, err := h.readDB.GetUserByLinkedAccountRemoteUserIDandSource(tx, req.RemoteUserID, rs.ID)
		if err != nil {
			return errors.Errorf("failed to get user for remote user id %q and remote source %q: %w", req.RemoteUserID, rs.ID, err)
		}
		if user != nil {
			return util.NewErrBadRequest(errors.Errorf("user for remote user id %q for remote source %q already exists", req.RemoteUserID, req.RemoteSourceName))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if user.LinkedAccounts == nil {
		user.LinkedAccounts = make(map[string]*types.LinkedAccount)
	}

	la := &types.LinkedAccount{
		ID:                         uuid.NewV4().String(),
		RemoteSourceID:             rs.ID,
		RemoteUserID:               req.RemoteUserID,
		RemoteUserName:             req.RemoteUserName,
		UserAccessToken:            req.UserAccessToken,
		Oauth2AccessToken:          req.Oauth2AccessToken,
		Oauth2RefreshToken:         req.Oauth2RefreshToken,
		Oauth2AccessTokenExpiresAt: req.Oauth2AccessTokenExpiresAt,
	}

	user.LinkedAccounts[la.ID] = la

	userj, err := json.Marshal(user)
	if err != nil {
		return nil, errors.Errorf("failed to marshal user: %w", err)
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeUser),
			ID:         user.ID,
			Data:       userj,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return la, err
}

func (h *ActionHandler) DeleteUserLA(ctx context.Context, userRef, laID string) error {
	if userRef == "" {
		return util.NewErrBadRequest(errors.Errorf("user ref  required"))
	}
	if laID == "" {
		return util.NewErrBadRequest(errors.Errorf("user linked account id required"))
	}

	var user *types.User

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		user, err = h.readDB.GetUser(tx, userRef)
		if err != nil {
			return err
		}
		if user == nil {
			return util.NewErrBadRequest(errors.Errorf("user %q doesn't exist", userRef))
		}

		// changegroup is the userid
		cgNames := []string{util.EncodeSha256Hex("userid-" + user.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	_, ok := user.LinkedAccounts[laID]
	if !ok {
		return util.NewErrBadRequest(errors.Errorf("linked account id %q for user %q doesn't exist", laID, userRef))
	}

	delete(user.LinkedAccounts, laID)

	userj, err := json.Marshal(user)
	if err != nil {
		return errors.Errorf("failed to marshal user: %w", err)
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeUser),
			ID:         user.ID,
			Data:       userj,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return err
}

type UpdateUserLARequest struct {
	UserRef string

	LinkedAccountID            string
	RemoteUserID               string
	RemoteUserName             string
	UserAccessToken            string
	Oauth2AccessToken          string
	Oauth2RefreshToken         string
	Oauth2AccessTokenExpiresAt time.Time
}

func (h *ActionHandler) UpdateUserLA(ctx context.Context, req *UpdateUserLARequest) (*types.LinkedAccount, error) {
	if req.UserRef == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("user ref required"))
	}

	var user *types.User
	var rs *types.RemoteSource

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		user, err = h.readDB.GetUser(tx, req.UserRef)
		if err != nil {
			return err
		}
		if user == nil {
			return util.NewErrBadRequest(errors.Errorf("user %q doesn't exist", req.UserRef))
		}

		// changegroup is the userid
		cgNames := []string{util.EncodeSha256Hex("userid-" + user.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		la, ok := user.LinkedAccounts[req.LinkedAccountID]
		if !ok {
			return util.NewErrBadRequest(errors.Errorf("linked account id %q for user %q doesn't exist", req.LinkedAccountID, user.Name))
		}

		rs, err = h.readDB.GetRemoteSource(tx, la.RemoteSourceID)
		if err != nil {
			return err
		}
		if rs == nil {
			return util.NewErrBadRequest(errors.Errorf("remote source with id %q doesn't exist", la.RemoteSourceID))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	la := user.LinkedAccounts[req.LinkedAccountID]

	la.RemoteUserID = req.RemoteUserID
	la.RemoteUserName = req.RemoteUserName
	la.UserAccessToken = req.UserAccessToken
	la.Oauth2AccessToken = req.Oauth2AccessToken
	la.Oauth2RefreshToken = req.Oauth2RefreshToken
	la.Oauth2AccessTokenExpiresAt = req.Oauth2AccessTokenExpiresAt

	userj, err := json.Marshal(user)
	if err != nil {
		return nil, errors.Errorf("failed to marshal user: %w", err)
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeUser),
			ID:         user.ID,
			Data:       userj,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return la, err
}

func (h *ActionHandler) CreateUserToken(ctx context.Context, userRef, tokenName string) (string, error) {
	if userRef == "" {
		return "", util.NewErrBadRequest(errors.Errorf("user ref required"))
	}
	if tokenName == "" {
		return "", util.NewErrBadRequest(errors.Errorf("token name required"))
	}

	var user *types.User

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		user, err = h.readDB.GetUser(tx, userRef)
		if err != nil {
			return err
		}
		if user == nil {
			return util.NewErrBadRequest(errors.Errorf("user %q doesn't exist", userRef))
		}

		// changegroup is the userid
		cgNames := []string{util.EncodeSha256Hex("userid-" + user.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return "", err
	}
	if user.Tokens != nil {
		if _, ok := user.Tokens[tokenName]; ok {
			return "", util.NewErrBadRequest(errors.Errorf("token %q for user %q already exists", tokenName, userRef))
		}
	}

	if user.Tokens == nil {
		user.Tokens = make(map[string]string)
	}

	token := util.EncodeSha1Hex(uuid.NewV4().String())
	user.Tokens[tokenName] = token

	userj, err := json.Marshal(user)
	if err != nil {
		return "", errors.Errorf("failed to marshal user: %w", err)
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeUser),
			ID:         user.ID,
			Data:       userj,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return token, err
}

func (h *ActionHandler) DeleteUserToken(ctx context.Context, userRef, tokenName string) error {
	if userRef == "" {
		return util.NewErrBadRequest(errors.Errorf("user ref required"))
	}
	if tokenName == "" {
		return util.NewErrBadRequest(errors.Errorf("token name required"))
	}

	var user *types.User

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		user, err = h.readDB.GetUser(tx, userRef)
		if err != nil {
			return err
		}
		if user == nil {
			return util.NewErrBadRequest(errors.Errorf("user %q doesn't exist", userRef))
		}

		// changegroup is the userid
		cgNames := []string{util.EncodeSha256Hex("userid-" + user.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	_, ok := user.Tokens[tokenName]
	if !ok {
		return util.NewErrBadRequest(errors.Errorf("token %q for user %q doesn't exist", tokenName, userRef))
	}

	delete(user.Tokens, tokenName)

	userj, err := json.Marshal(user)
	if err != nil {
		return errors.Errorf("failed to marshal user: %w", err)
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeUser),
			ID:         user.ID,
			Data:       userj,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return err
}

type UserOrgsResponse struct {
	Organization *types.Organization
	Role         types.MemberRole
}

func userOrgsResponse(userOrg *readdb.UserOrg) *UserOrgsResponse {
	return &UserOrgsResponse{
		Organization: userOrg.Organization,
		Role:         userOrg.Role,
	}
}

func (h *ActionHandler) GetUserOrgs(ctx context.Context, userRef string) ([]*UserOrgsResponse, error) {
	var userOrgs []*readdb.UserOrg
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		user, err := h.readDB.GetUser(tx, userRef)
		if err != nil {
			return err
		}
		if user == nil {
			return util.NewErrNotExist(errors.Errorf("user %q doesn't exist", userRef))
		}

		userOrgs, err = h.readDB.GetUserOrgs(tx, user.ID)
		return err
	})
	if err != nil {
		return nil, err
	}

	res := make([]*UserOrgsResponse, len(userOrgs))
	for i, userOrg := range userOrgs {
		res[i] = userOrgsResponse(userOrg)
	}

	return res, nil
}
