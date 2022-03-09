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

	"agola.io/agola/internal/datamanager"
	"agola.io/agola/internal/dbold"
	"agola.io/agola/internal/errors"

	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	"github.com/gofrs/uuid"
)

func (h *ActionHandler) ValidateRemoteSourceReq(ctx context.Context, req *CreateUpdateRemoteSourceRequest) error {
	if req.Name == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource name required"))
	}
	if !util.ValidateName(req.Name) {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid remotesource name %q", req.Name))
	}

	if req.Name == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource name required"))
	}
	if req.APIURL == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource api url required"))
	}
	if req.Type == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource type required"))
	}
	if req.AuthType == "" {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource auth type required"))
	}

	// validate if the remotesource type supports the required auth type
	if !types.SourceSupportsAuthType(types.RemoteSourceType(req.Type), types.RemoteSourceAuthType(req.AuthType)) {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource type %q doesn't support auth type %q", req.Type, req.AuthType))
	}
	if req.AuthType == types.RemoteSourceAuthTypeOauth2 {
		if req.Oauth2ClientID == "" {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource oauth2clientid required for auth type %q", types.RemoteSourceAuthTypeOauth2))
		}
		if req.Oauth2ClientSecret == "" {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource oauth2clientsecret required for auth type %q", types.RemoteSourceAuthTypeOauth2))
		}
	}

	return nil
}

type CreateUpdateRemoteSourceRequest struct {
	Name                string
	APIURL              string
	SkipVerify          bool
	Type                types.RemoteSourceType
	AuthType            types.RemoteSourceAuthType
	Oauth2ClientID      string
	Oauth2ClientSecret  string
	SSHHostKey          string
	SkipSSHHostKeyCheck bool
	RegistrationEnabled *bool
	LoginEnabled        *bool
}

func (h *ActionHandler) CreateRemoteSource(ctx context.Context, req *CreateUpdateRemoteSourceRequest) (*types.RemoteSource, error) {
	if err := h.ValidateRemoteSourceReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the remotesource name
	cgNames := []string{util.EncodeSha256Hex("remotesourcename-" + req.Name)}

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return errors.WithStack(err)
		}

		// check duplicate remoteSource name
		u, err := h.readDB.GetRemoteSourceByName(tx, req.Name)
		if err != nil {
			return errors.WithStack(err)
		}
		if u != nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource %q already exists", u.Name))
		}
		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	remoteSource := &types.RemoteSource{}
	remoteSource.ID = uuid.Must(uuid.NewV4()).String()
	remoteSource.Name = req.Name
	remoteSource.APIURL = req.APIURL
	remoteSource.SkipVerify = req.SkipVerify
	remoteSource.Type = req.Type
	remoteSource.AuthType = req.AuthType
	remoteSource.Oauth2ClientID = req.Oauth2ClientID
	remoteSource.Oauth2ClientSecret = req.Oauth2ClientSecret
	remoteSource.SSHHostKey = req.SSHHostKey
	remoteSource.SkipSSHHostKeyCheck = req.SkipSSHHostKeyCheck
	remoteSource.RegistrationEnabled = req.RegistrationEnabled
	remoteSource.LoginEnabled = req.LoginEnabled

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

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return remoteSource, errors.WithStack(err)
}

func (h *ActionHandler) UpdateRemoteSource(ctx context.Context, remoteSourceRef string, req *CreateUpdateRemoteSourceRequest) (*types.RemoteSource, error) {
	if err := h.ValidateRemoteSourceReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var cgt *datamanager.ChangeGroupsUpdateToken

	var remoteSource *types.RemoteSource
	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error

		// check remotesource exists
		remoteSource, err = h.readDB.GetRemoteSourceByName(tx, remoteSourceRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if remoteSource == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource with ref %q doesn't exist", remoteSourceRef))
		}

		if remoteSource.Name != req.Name {
			// check duplicate remoteSource name
			u, err := h.readDB.GetRemoteSourceByName(tx, req.Name)
			if err != nil {
				return errors.WithStack(err)
			}
			if u != nil {
				return util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource %q already exists", u.Name))
			}
		}

		remoteSource.Name = req.Name
		remoteSource.APIURL = req.APIURL
		remoteSource.SkipVerify = req.SkipVerify
		remoteSource.Type = req.Type
		remoteSource.AuthType = req.AuthType
		remoteSource.Oauth2ClientID = req.Oauth2ClientID
		remoteSource.Oauth2ClientSecret = req.Oauth2ClientSecret
		remoteSource.SSHHostKey = req.SSHHostKey
		remoteSource.SkipSSHHostKeyCheck = req.SkipSSHHostKeyCheck
		remoteSource.RegistrationEnabled = req.RegistrationEnabled
		remoteSource.LoginEnabled = req.LoginEnabled

		// changegroup is the remotesource id and also name since we could change the
		// name so concurrently updating on the new name
		cgNames := []string{util.EncodeSha256Hex("remotesourcename-" + remoteSource.Name), util.EncodeSha256Hex("remotesourceid-" + remoteSource.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

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

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return remoteSource, errors.WithStack(err)
}

func (h *ActionHandler) DeleteRemoteSource(ctx context.Context, remoteSourceName string) error {
	var remoteSource *types.RemoteSource
	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error

		// check remoteSource existance
		remoteSource, err = h.readDB.GetRemoteSourceByName(tx, remoteSourceName)
		if err != nil {
			return errors.WithStack(err)
		}
		if remoteSource == nil {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource %q doesn't exist", remoteSourceName))
		}

		// changegroup is the remotesource id
		cgNames := []string{util.EncodeSha256Hex("remotesourceid-" + remoteSource.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypeDelete,
			DataType:   string(types.ConfigTypeRemoteSource),
			ID:         remoteSource.ID,
		},
	}

	// changegroup is all the remotesources
	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return errors.WithStack(err)
}
