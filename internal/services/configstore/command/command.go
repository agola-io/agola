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

	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/configstore/common"
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

func (s *CommandHandler) CreateProject(ctx context.Context, project *types.Project) (*types.Project, error) {
	if project.Name == "" {
		return nil, errors.Errorf("project name required")
	}
	if project.OwnerType == "" {
		return nil, errors.Errorf("project ownertype required")
	}
	if project.OwnerID == "" {
		return nil, errors.Errorf("project ownerid required")
	}
	if !types.IsValidOwnerType(project.OwnerType) {
		return nil, errors.Errorf("invalid project ownertype %q", project.OwnerType)
	}

	var cgt *wal.ChangeGroupsUpdateToken
	cgNames := []string{project.OwnerID}

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check owner exists
		switch project.OwnerType {
		case types.OwnerTypeUser:
			user, err := s.readDB.GetUser(tx, project.OwnerID)
			if err != nil {
				return err
			}
			if user == nil {
				return errors.Errorf("user id %q doesn't exist", project.OwnerID)
			}
		case types.OwnerTypeOrganization:
			org, err := s.readDB.GetOrg(tx, project.OwnerID)
			if err != nil {
				return err
			}
			if org == nil {
				return errors.Errorf("organization id %q doesn't exist", project.OwnerID)
			}
		}
		// check duplicate project name
		p, err := s.readDB.GetOwnerProjectByName(tx, project.OwnerID, project.Name)
		if err != nil {
			return err
		}
		if p != nil {
			return errors.Errorf("project with name %q for %s with id %q already exists", p.Name, project.OwnerType, project.OwnerID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	project.ID = uuid.NewV4().String()

	pcj, err := json.Marshal(project)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal project")
	}
	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypePut,
			Path:       common.StorageProjectFile(project.ID),
			Data:       pcj,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return project, err
}

func (s *CommandHandler) DeleteProject(ctx context.Context, projectID string) error {
	var project *types.Project

	var cgt *wal.ChangeGroupsUpdateToken
	cgNames := []string{project.OwnerID}

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check project existance
		project, err = s.readDB.GetProject(tx, projectID)
		if err != nil {
			return err
		}
		if project == nil {
			return errors.Errorf("project %q doesn't exist", projectID)
		}
		return nil
	})
	if err != nil {
		return err
	}

	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypeDelete,
			Path:       common.StorageProjectFile(project.ID),
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return err
}

func (s *CommandHandler) CreateUser(ctx context.Context, user *types.User) (*types.User, error) {
	if user.UserName == "" {
		return nil, errors.Errorf("user name required")
	}

	var cgt *wal.ChangeGroupsUpdateToken
	cgNames := []string{user.UserName}

	// must do all the check in a single transaction to avoid concurrent changes
	err := s.readDB.Do(func(tx *db.Tx) error {
		var err error
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check duplicate user name
		u, err := s.readDB.GetUserByName(tx, user.UserName)
		if err != nil {
			return err
		}
		if u != nil {
			return errors.Errorf("user with name %q already exists", u.UserName)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	user.ID = uuid.NewV4().String()

	userj, err := json.Marshal(user)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal user")
	}
	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypePut,
			Path:       common.StorageUserFile(user.ID),
			Data:       userj,
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
			return errors.Errorf("user %q doesn't exist", userName)
		}
		return nil
	})
	if err != nil {
		return err
	}

	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypeDelete,
			Path:       common.StorageUserFile(user.ID),
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
		return nil, errors.Errorf("user name required")
	}
	if req.RemoteSourceName == "" {
		return nil, errors.Errorf("remote source name required")
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
			return errors.Errorf("user %q doesn't exist", req.UserName)
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
			return errors.Errorf("remote source %q doesn't exist", req.RemoteSourceName)
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
			Path:       common.StorageUserFile(user.ID),
			Data:       userj,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return la, err
}

func (s *CommandHandler) DeleteUserLA(ctx context.Context, userName, laID string) error {
	if userName == "" {
		return errors.Errorf("user name required")
	}
	if laID == "" {
		return errors.Errorf("user linked account id required")
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
			return errors.Errorf("user %q doesn't exist", userName)
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
		return errors.Errorf("linked account id %q for user %q doesn't exist", laID, userName)
	}

	delete(user.LinkedAccounts, laID)

	userj, err := json.Marshal(user)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal user")
	}
	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypePut,
			Path:       common.StorageUserFile(user.ID),
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
		return nil, errors.Errorf("user name required")
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
			return errors.Errorf("user %q doesn't exist", req.UserName)
		}

		cgNames := []string{user.ID}
		cgt, err = s.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		la, ok := user.LinkedAccounts[req.LinkedAccountID]
		if !ok {
			return errors.Errorf("linked account id %q for user %q doesn't exist", req.LinkedAccountID, user.UserName)
		}

		rs, err = s.readDB.GetRemoteSource(tx, la.RemoteSourceID)
		if err != nil {
			return err
		}
		if rs == nil {
			return errors.Errorf("remote source with id %q doesn't exist", la.RemoteSourceID)
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
			Path:       common.StorageUserFile(user.ID),
			Data:       userj,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return la, err
}

func (s *CommandHandler) CreateUserToken(ctx context.Context, userName, tokenName string) (string, error) {
	if userName == "" {
		return "", errors.Errorf("user name required")
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
			return errors.Errorf("user %q doesn't exist", userName)
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
			Path:       common.StorageUserFile(user.ID),
			Data:       userj,
		},
	}

	// changegroup is the userid
	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return token, err
}

func (s *CommandHandler) CreateRemoteSource(ctx context.Context, remoteSource *types.RemoteSource) (*types.RemoteSource, error) {
	if remoteSource.Name == "" {
		return nil, errors.Errorf("remotesource name required")
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
			return errors.Errorf("remoteSource %q already exists", u.Name)
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
			Path:       common.StorageRemoteSourceFile(remoteSource.ID),
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
			return errors.Errorf("remotesource %q doesn't exist", remoteSourceName)
		}
		return nil
	})
	if err != nil {
		return err
	}

	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypeDelete,
			Path:       common.StorageRemoteSourceFile(remoteSource.ID),
		},
	}

	// changegroup is all the remote sources
	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return err
}

func (s *CommandHandler) CreateOrg(ctx context.Context, org *types.Organization) (*types.Organization, error) {
	if org.Name == "" {
		return nil, errors.Errorf("org name required")
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
			return errors.Errorf("org %q already exists", u.Name)
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
	actions := []*wal.Action{
		{
			ActionType: wal.ActionTypePut,
			Path:       common.StorageOrgFile(org.ID),
			Data:       orgj,
		},
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return org, err
}

func (s *CommandHandler) DeleteOrg(ctx context.Context, orgName string) error {
	var org *types.Organization
	var projects []*types.Project

	var cgt *wal.ChangeGroupsUpdateToken
	cgNames := []string{org.ID}

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
			return errors.Errorf("org %q doesn't exist", orgName)
		}
		// get org projects
		projects, err = s.readDB.GetOwnerProjects(tx, org.ID, "", 0, false)
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
			Path:       common.StorageOrgFile(org.ID),
		},
	}
	// delete all org projects
	for _, project := range projects {
		actions = append(actions, &wal.Action{
			ActionType: wal.ActionTypeDelete,
			Path:       common.StorageProjectFile(project.ID),
		})
	}

	_, err = s.wal.WriteWal(ctx, actions, cgt)
	return err
}
