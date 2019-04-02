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

package command

import (
	"context"
	"encoding/json"
	"path"

	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/configstore/readdb"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"
	"github.com/sorintlab/agola/internal/wal"

	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"go.uber.org/zap"
)

type CommandHandler struct {
	log    *zap.SugaredLogger
	readDB *readdb.ReadDB
	wal    *wal.WalManager
}

func NewCommandHandler(logger *zap.Logger, readDB *readdb.ReadDB, wal *wal.WalManager) *CommandHandler {
	return &CommandHandler{
		log:    logger.Sugar(),
		readDB: readDB,
		wal:    wal,
	}
}

func (s *CommandHandler) CreateProjectGroup(ctx context.Context, projectGroup *types.ProjectGroup) (*types.ProjectGroup, error) {
	if projectGroup.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("project group name required"))
	}
	if projectGroup.Parent.ID == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("project group parent id required"))
	}

	var cgt *wal.ChangeGroupsUpdateToken

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		parentProjectGroup, err := s.readDB.GetProjectGroup(tx, projectGroup.Parent.ID)
		if err != nil {
			return err
		}
		if parentProjectGroup == nil {
			return util.NewErrBadRequest(errors.Errorf("project group with id %q doesn't exist", projectGroup.Parent.ID))
		}
		projectGroup.Parent.ID = parentProjectGroup.ID

		groupPath, err := s.readDB.GetProjectGroupPath(tx, parentProjectGroup)
		if err != nil {
			return err
		}
		pp := path.Join(groupPath, projectGroup.Name)

		cgNames := []string{pp}
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check duplicate project name
		p, err := s.readDB.GetProjectByName(tx, projectGroup.Parent.ID, projectGroup.Name)
		if err != nil {
			return err
		}
		if p != nil {
			return util.NewErrBadRequest(errors.Errorf("project with name %q, path %q already exists", p.Name, pp))
		}
		// check duplicate project group name
		pg, err := s.readDB.GetProjectGroupByName(tx, projectGroup.Parent.ID, projectGroup.Name)
		if err != nil {
			return err
		}
		if pg != nil {
			return util.NewErrBadRequest(errors.Errorf("project group with name %q, path %q already exists", pg.Name, pp))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	projectGroup.ID = uuid.NewV4().String()
	projectGroup.Parent.Type = types.ConfigTypeProjectGroup

	pcj, err := json.Marshal(projectGroup)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal projectGroup")
	}
	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypePut,
			DataType:   string(types.ConfigTypeProjectGroup),
			ID:         projectGroup.ID,
			Data:       pcj,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return projectGroup, err
}

func (s *CommandHandler) CreateProject(ctx context.Context, project *types.Project) (*types.Project, error) {
	if project.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("project name required"))
	}
	if project.Parent.ID == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("project parent id required"))
	}

	var cgt *wal.ChangeGroupsUpdateToken

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		group, err := s.readDB.GetProjectGroup(tx, project.Parent.ID)
		if err != nil {
			return err
		}
		if group == nil {
			return util.NewErrBadRequest(errors.Errorf("project group with id %q doesn't exist", project.Parent.ID))
		}
		project.Parent.ID = group.ID

		groupPath, err := s.readDB.GetProjectGroupPath(tx, group)
		if err != nil {
			return err
		}
		pp := path.Join(groupPath, project.Name)

		cgNames := []string{pp}
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check duplicate project name
		p, err := s.readDB.GetProjectByName(tx, project.Parent.ID, project.Name)
		if err != nil {
			return err
		}
		if p != nil {
			return util.NewErrBadRequest(errors.Errorf("project with name %q, path %q already exists", p.Name, pp))
		}
		// check duplicate project group name
		pg, err := s.readDB.GetProjectGroupByName(tx, project.Parent.ID, project.Name)
		if err != nil {
			return err
		}
		if pg != nil {
			return util.NewErrBadRequest(errors.Errorf("project group with name %q, path %q already exists", pg.Name, pp))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	project.ID = uuid.NewV4().String()
	project.Parent.Type = types.ConfigTypeProjectGroup

	pcj, err := json.Marshal(project)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal project")
	}
	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypePut,
			DataType:   string(types.ConfigTypeProject),
			ID:         project.ID,
			Data:       pcj,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return project, err
}

func (s *CommandHandler) DeleteProject(ctx context.Context, projectRef string) error {
	var project *types.Project

	var cgt *wal.ChangeGroupsUpdateToken

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error

		// check project existance
		project, err = s.readDB.GetProject(tx, projectRef)
		if err != nil {
			return err
		}
		if project == nil {
			return util.NewErrBadRequest(errors.Errorf("project %q doesn't exist", projectRef))
		}
		group, err := s.readDB.GetProjectGroup(tx, project.Parent.ID)
		if err != nil {
			return err
		}

		cgNames := []string{group.ID}
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	// TODO(sgotti) delete project secrets/variables
	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypeDelete,
			DataType:   string(types.ConfigTypeProject),
			ID:         project.ID,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return err
}

type CreateUserRequest struct {
	UserName string

	CreateUserLARequest *CreateUserLARequest
}

func (s *CommandHandler) CreateUser(ctx context.Context, req *CreateUserRequest) (*types.User, error) {
	if req.UserName == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("user name required"))
	}

	var cgt *wal.ChangeGroupsUpdateToken
	cgNames := []string{req.UserName}
	var rs *types.RemoteSource

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check duplicate user name
		u, err := s.readDB.GetUserByName(tx, req.UserName)
		if err != nil {
			return err
		}
		if u != nil {
			return util.NewErrBadRequest(errors.Errorf("user with name %q already exists", u.UserName))
		}

		if req.CreateUserLARequest != nil {
			rs, err = s.readDB.GetRemoteSourceByName(tx, req.CreateUserLARequest.RemoteSourceName)
			if err != nil {
				return err
			}
			if rs == nil {
				return util.NewErrBadRequest(errors.Errorf("remote source %q doesn't exist", req.CreateUserLARequest.RemoteSourceName))
			}
			user, err := s.readDB.GetUserByLinkedAccountRemoteUserIDandSource(tx, req.CreateUserLARequest.RemoteUserID, rs.ID)
			if err != nil {
				return errors.Wrapf(err, "failed to get user for remote user id %q and remote source %q", req.CreateUserLARequest.RemoteUserID, rs.ID)
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
		ID:       uuid.NewV4().String(),
		UserName: req.UserName,
	}
	if req.CreateUserLARequest != nil {
		if user.LinkedAccounts == nil {
			user.LinkedAccounts = make(map[string]*types.LinkedAccount)
		}

		la := &types.LinkedAccount{
			ID:                 uuid.NewV4().String(),
			RemoteSourceID:     rs.ID,
			RemoteUserID:       req.CreateUserLARequest.RemoteUserID,
			RemoteUserName:     req.CreateUserLARequest.RemoteUserName,
			UserAccessToken:    req.CreateUserLARequest.UserAccessToken,
			Oauth2AccessToken:  req.CreateUserLARequest.Oauth2AccessToken,
			Oauth2RefreshToken: req.CreateUserLARequest.Oauth2RefreshToken,
		}

		user.LinkedAccounts[la.ID] = la
	}

	userj, err := json.Marshal(user)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal user")
	}

	pg := &types.ProjectGroup{
		ID: uuid.NewV4().String(),
		Parent: types.Parent{
			Type: types.ConfigTypeUser,
			ID:   user.ID,
		},
	}
	pgj, err := json.Marshal(pg)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal project group")
	}

	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypePut,
			DataType:   string(types.ConfigTypeUser),
			ID:         user.ID,
			Data:       userj,
		},
		{
			ActionType: wal.ActionTypePut,
			DataType:   string(types.ConfigTypeProjectGroup),
			ID:         pg.ID,
			Data:       pgj,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return user, err
}

func (s *CommandHandler) DeleteUser(ctx context.Context, userName string) error {
	var user *types.User

	var cgt *wal.ChangeGroupsUpdateToken
	cgNames := []string{user.UserName}

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check user existance
		user, err = s.readDB.GetUserByName(tx, userName)
		if err != nil {
			return err
		}
		if user == nil {
			return util.NewErrBadRequest(errors.Errorf("user %q doesn't exist", userName))
		}
		return nil
	})
	if err != nil {
		return err
	}

	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypeDelete,
			DataType:   string(types.ConfigTypeUser),
			ID:         user.ID,
		},
	}

	// changegroup is the username (and in future the email) to ensure no
	// concurrent user creation/modification using the same name
	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return err
}

type CreateUserLARequest struct {
	UserName           string
	RemoteSourceName   string
	RemoteUserID       string
	RemoteUserName     string
	UserAccessToken    string
	Oauth2AccessToken  string
	Oauth2RefreshToken string
}

func (s *CommandHandler) CreateUserLA(ctx context.Context, req *CreateUserLARequest) (*types.LinkedAccount, error) {
	if req.UserName == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("user name required"))
	}
	if req.RemoteSourceName == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("remote source name required"))
	}

	var user *types.User
	var rs *types.RemoteSource

	var cgt *wal.ChangeGroupsUpdateToken

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		user, err = s.readDB.GetUserByName(tx, req.UserName)
		if err != nil {
			return err
		}
		if user == nil {
			return util.NewErrBadRequest(errors.Errorf("user %q doesn't exist", req.UserName))
		}

		cgNames := []string{user.ID}
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		rs, err = s.readDB.GetRemoteSourceByName(tx, req.RemoteSourceName)
		if err != nil {
			return err
		}
		if rs == nil {
			return util.NewErrBadRequest(errors.Errorf("remote source %q doesn't exist", req.RemoteSourceName))
		}

		user, err := s.readDB.GetUserByLinkedAccountRemoteUserIDandSource(tx, req.RemoteUserID, rs.ID)
		if err != nil {
			return errors.Wrapf(err, "failed to get user for remote user id %q and remote source %q", req.RemoteUserID, rs.ID)
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
		ID:                 uuid.NewV4().String(),
		RemoteSourceID:     rs.ID,
		RemoteUserID:       req.RemoteUserID,
		RemoteUserName:     req.RemoteUserName,
		UserAccessToken:    req.UserAccessToken,
		Oauth2AccessToken:  req.Oauth2AccessToken,
		Oauth2RefreshToken: req.Oauth2RefreshToken,
	}

	user.LinkedAccounts[la.ID] = la

	userj, err := json.Marshal(user)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal user")
	}
	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypePut,
			DataType:   string(types.ConfigTypeUser),
			ID:         user.ID,
			Data:       userj,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return la, err
}

func (s *CommandHandler) DeleteUserLA(ctx context.Context, userName, laID string) error {
	if userName == "" {
		return util.NewErrBadRequest(errors.Errorf("user name required"))
	}
	if laID == "" {
		return util.NewErrBadRequest(errors.Errorf("user linked account id required"))
	}

	var user *types.User

	var cgt *wal.ChangeGroupsUpdateToken

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		user, err = s.readDB.GetUserByName(tx, userName)
		if err != nil {
			return err
		}
		if user == nil {
			return util.NewErrBadRequest(errors.Errorf("user %q doesn't exist", userName))
		}

		cgNames := []string{user.ID}
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
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
		return util.NewErrBadRequest(errors.Errorf("linked account id %q for user %q doesn't exist", laID, userName))
	}

	delete(user.LinkedAccounts, laID)

	userj, err := json.Marshal(user)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal user")
	}
	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypePut,
			DataType:   string(types.ConfigTypeUser),
			ID:         user.ID,
			Data:       userj,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return err
}

type UpdateUserLARequest struct {
	UserName           string
	LinkedAccountID    string
	RemoteUserID       string
	RemoteUserName     string
	UserAccessToken    string
	Oauth2AccessToken  string
	Oauth2RefreshToken string
}

func (s *CommandHandler) UpdateUserLA(ctx context.Context, req *UpdateUserLARequest) (*types.LinkedAccount, error) {
	if req.UserName == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("user name required"))
	}

	var user *types.User
	var rs *types.RemoteSource

	var cgt *wal.ChangeGroupsUpdateToken

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		user, err = s.readDB.GetUserByName(tx, req.UserName)
		if err != nil {
			return err
		}
		if user == nil {
			return util.NewErrBadRequest(errors.Errorf("user %q doesn't exist", req.UserName))
		}

		cgNames := []string{user.ID}
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		la, ok := user.LinkedAccounts[req.LinkedAccountID]
		if !ok {
			return util.NewErrBadRequest(errors.Errorf("linked account id %q for user %q doesn't exist", req.LinkedAccountID, user.UserName))
		}

		rs, err = s.readDB.GetRemoteSource(tx, la.RemoteSourceID)
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

	userj, err := json.Marshal(user)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal user")
	}
	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypePut,
			DataType:   string(types.ConfigTypeUser),
			ID:         user.ID,
			Data:       userj,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return la, err
}

func (s *CommandHandler) CreateUserToken(ctx context.Context, userName, tokenName string) (string, error) {
	if userName == "" {
		return "", util.NewErrBadRequest(errors.Errorf("user name required"))
	}

	var user *types.User

	var cgt *wal.ChangeGroupsUpdateToken

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		user, err = s.readDB.GetUserByName(tx, userName)
		if err != nil {
			return err
		}
		if user == nil {
			return util.NewErrBadRequest(errors.Errorf("user %q doesn't exist", userName))
		}

		cgNames := []string{user.ID}
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return "", err
	}

	if user.Tokens == nil {
		user.Tokens = make(map[string]string)
	}

	token := util.EncodeSha1Hex(uuid.NewV4().String())
	user.Tokens[tokenName] = token

	userj, err := json.Marshal(user)
	if err != nil {
		return "", errors.Wrapf(err, "failed to marshal user")
	}
	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypePut,
			DataType:   string(types.ConfigTypeUser),
			ID:         user.ID,
			Data:       userj,
		},
	}

	// changegroup is the userid
	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return token, err
}

func (s *CommandHandler) CreateRemoteSource(ctx context.Context, remoteSource *types.RemoteSource) (*types.RemoteSource, error) {
	if remoteSource.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("remotesource name required"))
	}

	var cgt *wal.ChangeGroupsUpdateToken
	cgNames := []string{remoteSource.Name}

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check duplicate remoteSource name
		u, err := s.readDB.GetRemoteSourceByName(tx, remoteSource.Name)
		if err != nil {
			return err
		}
		if u != nil {
			return util.NewErrBadRequest(errors.Errorf("remoteSource %q already exists", u.Name))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	remoteSource.ID = uuid.NewV4().String()

	rsj, err := json.Marshal(remoteSource)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal remotesource")
	}
	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypePut,
			DataType:   string(types.ConfigTypeRemoteSource),
			ID:         remoteSource.ID,
			Data:       rsj,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return remoteSource, err
}

func (s *CommandHandler) DeleteRemoteSource(ctx context.Context, remoteSourceName string) error {
	var remoteSource *types.RemoteSource

	var cgt *wal.ChangeGroupsUpdateToken
	cgNames := []string{remoteSource.ID}

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check remoteSource existance
		remoteSource, err = s.readDB.GetRemoteSourceByName(tx, remoteSourceName)
		if err != nil {
			return err
		}
		if remoteSource == nil {
			return util.NewErrBadRequest(errors.Errorf("remotesource %q doesn't exist", remoteSourceName))
		}
		return nil
	})
	if err != nil {
		return err
	}

	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypeDelete,
			DataType:   string(types.ConfigTypeRemoteSource),
			ID:         remoteSource.ID,
		},
	}

	// changegroup is all the remote sources
	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return err
}

func (s *CommandHandler) CreateOrg(ctx context.Context, org *types.Organization) (*types.Organization, error) {
	if org.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("org name required"))
	}

	var cgt *wal.ChangeGroupsUpdateToken
	cgNames := []string{org.Name}

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check duplicate org name
		u, err := s.readDB.GetOrgByName(tx, org.Name)
		if err != nil {
			return err
		}
		if u != nil {
			return util.NewErrBadRequest(errors.Errorf("org %q already exists", u.Name))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	org.ID = uuid.NewV4().String()
	orgj, err := json.Marshal(org)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal org")
	}

	pg := &types.ProjectGroup{
		ID: uuid.NewV4().String(),
		Parent: types.Parent{
			Type: types.ConfigTypeOrg,
			ID:   org.ID,
		},
	}
	pgj, err := json.Marshal(pg)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal project group")
	}
	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypePut,
			DataType:   string(types.ConfigTypeOrg),
			ID:         org.ID,
			Data:       orgj,
		},
		{
			ActionType: wal.ActionTypePut,
			DataType:   string(types.ConfigTypeProjectGroup),
			ID:         pg.ID,
			Data:       pgj,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return org, err
}

func (s *CommandHandler) DeleteOrg(ctx context.Context, orgName string) error {
	var org *types.Organization
	var projects []*types.Project

	var cgt *wal.ChangeGroupsUpdateToken
	cgNames := []string{orgName}

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check org existance
		org, err = s.readDB.GetOrgByName(tx, orgName)
		if err != nil {
			return err
		}
		if org == nil {
			return util.NewErrBadRequest(errors.Errorf("org %q doesn't exist", orgName))
		}
		// TODO(sgotti) delete all project groups, projects etc...
		return nil
	})
	if err != nil {
		return err
	}

	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypeDelete,
			DataType:   string(types.ConfigTypeOrg),
			ID:         org.ID,
		},
	}
	// delete all org projects
	for _, project := range projects {
		actions = append(actions, &wal.Action{
			ActionType: wal.ActionTypeDelete,
			DataType:   string(types.ConfigTypeProject),
			ID:         project.ID,
		})
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return err
}

func (s *CommandHandler) CreateSecret(ctx context.Context, secret *types.Secret) (*types.Secret, error) {
	if secret.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("secret name required"))
	}
	if secret.Parent.Type == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("secret parent type required"))
	}
	if secret.Parent.ID == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("secret parentid required"))
	}
	if secret.Parent.Type != types.ConfigTypeProject && secret.Parent.Type != types.ConfigTypeProjectGroup {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid secret parent type %q", secret.Parent.Type))
	}

	var cgt *wal.ChangeGroupsUpdateToken
	cgNames := []string{secret.Name}

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		parentID, err := s.readDB.ResolveConfigID(tx, secret.Parent.Type, secret.Parent.ID)
		if err != nil {
			return err
		}
		secret.Parent.ID = parentID

		// check duplicate secret name
		s, err := s.readDB.GetSecretByName(tx, secret.Parent.ID, secret.Name)
		if err != nil {
			return err
		}
		if s != nil {
			return util.NewErrBadRequest(errors.Errorf("secret with name %q for %s with id %q already exists", secret.Name, secret.Parent.Type, secret.Parent.ID))
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	secret.ID = uuid.NewV4().String()

	secretj, err := json.Marshal(secret)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal secret")
	}
	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypePut,
			DataType:   string(types.ConfigTypeSecret),
			ID:         secret.ID,
			Data:       secretj,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return secret, err
}

func (s *CommandHandler) DeleteSecret(ctx context.Context, parentType types.ConfigType, parentRef, secretName string) error {
	var secret *types.Secret

	var cgt *wal.ChangeGroupsUpdateToken

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		parentID, err := s.readDB.ResolveConfigID(tx, parentType, parentRef)
		if err != nil {
			return err
		}

		// check secret existance
		secret, err = s.readDB.GetSecretByName(tx, parentID, secretName)
		if err != nil {
			return err
		}
		if secret == nil {
			return util.NewErrBadRequest(errors.Errorf("secret with name %q doesn't exist", secretName))
		}

		cgNames := []string{secretName}
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypeDelete,
			DataType:   string(types.ConfigTypeSecret),
			ID:         secret.ID,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return err
}

func (s *CommandHandler) CreateVariable(ctx context.Context, variable *types.Variable) (*types.Variable, error) {
	if variable.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("variable name required"))
	}
	if len(variable.Values) == 0 {
		return nil, util.NewErrBadRequest(errors.Errorf("variable values required"))
	}
	if variable.Parent.Type == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("variable parent type required"))
	}
	if variable.Parent.ID == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("variable parent id required"))
	}
	if variable.Parent.Type != types.ConfigTypeProject && variable.Parent.Type != types.ConfigTypeProjectGroup {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid variable parent type %q", variable.Parent.Type))
	}

	var cgt *wal.ChangeGroupsUpdateToken
	cgNames := []string{variable.Name}

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		parentID, err := s.readDB.ResolveConfigID(tx, variable.Parent.Type, variable.Parent.ID)
		if err != nil {
			return err
		}
		variable.Parent.ID = parentID

		// check duplicate variable name
		s, err := s.readDB.GetVariableByName(tx, variable.Parent.ID, variable.Name)
		if err != nil {
			return err
		}
		if s != nil {
			return util.NewErrBadRequest(errors.Errorf("variable with name %q for %s with id %q already exists", variable.Name, variable.Parent.Type, variable.Parent.ID))
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	variable.ID = uuid.NewV4().String()

	variablej, err := json.Marshal(variable)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal variable")
	}
	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypePut,
			DataType:   string(types.ConfigTypeVariable),
			ID:         variable.ID,
			Data:       variablej,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return variable, err
}

func (s *CommandHandler) DeleteVariable(ctx context.Context, parentType types.ConfigType, parentRef, variableName string) error {
	var variable *types.Variable

	var cgt *wal.ChangeGroupsUpdateToken

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		parentID, err := s.readDB.ResolveConfigID(tx, parentType, parentRef)
		if err != nil {
			return err
		}

		// check variable existance
		variable, err = s.readDB.GetVariableByName(tx, parentID, variableName)
		if err != nil {
			return err
		}
		if variable == nil {
			return util.NewErrBadRequest(errors.Errorf("variable with name %q doesn't exist", variableName))
		}

		cgNames := []string{variableName}
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypeDelete,
			DataType:   string(types.ConfigTypeVariable),
			ID:         variable.ID,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return err
}
