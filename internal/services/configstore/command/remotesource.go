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

	"github.com/sorintlab/agola/internal/datamanager"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func (s *CommandHandler) CreateRemoteSource(ctx context.Context, remoteSource *types.RemoteSource) (*types.RemoteSource, error) {
	if remoteSource.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("remotesource name required"))
	}
	if !util.ValidateName(remoteSource.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid remotesource name %q", remoteSource.Name))
	}

	if remoteSource.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("remotesource name required"))
	}
	if remoteSource.APIURL == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("remotesource api url required"))
	}
	if remoteSource.Type == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("remotesource type required"))
	}
	if remoteSource.AuthType == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("remotesource auth type required"))
	}

	// validate if the remote source type supports the required auth type
	if !types.SourceSupportsAuthType(types.RemoteSourceType(remoteSource.Type), types.RemoteSourceAuthType(remoteSource.AuthType)) {
		return nil, util.NewErrBadRequest(errors.Errorf("remotesource type %q doesn't support auth type %q", remoteSource.Type, remoteSource.AuthType))
	}
	if remoteSource.AuthType == types.RemoteSourceAuthTypeOauth2 {
		if remoteSource.Oauth2ClientID == "" {
			return nil, util.NewErrBadRequest(errors.Errorf("remotesource oauth2clientid required for auth type %q", types.RemoteSourceAuthTypeOauth2))
		}
		if remoteSource.Oauth2ClientSecret == "" {
			return nil, util.NewErrBadRequest(errors.Errorf("remotesource oauth2clientsecret required for auth type %q", types.RemoteSourceAuthTypeOauth2))
		}
	}

	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the remotesource name
	cgNames := []string{util.EncodeSha256Hex("remotesourcename-" + remoteSource.Name)}

	// must do all the checks in a single transaction to avoid concurrent changes
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
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeRemoteSource),
			ID:         remoteSource.ID,
			Data:       rsj,
		},
	}

	_, err = s.dm.WriteWal(ctx, actions, cgt)
	return remoteSource, err
}

func (s *CommandHandler) DeleteRemoteSource(ctx context.Context, remoteSourceName string) error {
	var remoteSource *types.RemoteSource

	var cgt *datamanager.ChangeGroupsUpdateToken

	// changegroup is the remotesource id
	cgNames := []string{util.EncodeSha256Hex("remotesourceid-" + remoteSource.ID)}

	// must do all the checks in a single transaction to avoid concurrent changes
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

	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypeDelete,
			DataType:   string(types.ConfigTypeRemoteSource),
			ID:         remoteSource.ID,
		},
	}

	// changegroup is all the remote sources
	_, err = s.dm.WriteWal(ctx, actions, cgt)
	return err
}
