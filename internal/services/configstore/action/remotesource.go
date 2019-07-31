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
	"agola.io/agola/internal/db"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	uuid "github.com/satori/go.uuid"
	errors "golang.org/x/xerrors"
)

func (h *ActionHandler) ValidateRemoteSource(ctx context.Context, remoteSource *types.RemoteSource) error {
	if remoteSource.Name == "" {
		return util.NewErrBadRequest(errors.Errorf("remotesource name required"))
	}
	if !util.ValidateName(remoteSource.Name) {
		return util.NewErrBadRequest(errors.Errorf("invalid remotesource name %q", remoteSource.Name))
	}

	if remoteSource.Name == "" {
		return util.NewErrBadRequest(errors.Errorf("remotesource name required"))
	}
	if remoteSource.APIURL == "" {
		return util.NewErrBadRequest(errors.Errorf("remotesource api url required"))
	}
	if remoteSource.Type == "" {
		return util.NewErrBadRequest(errors.Errorf("remotesource type required"))
	}
	if remoteSource.AuthType == "" {
		return util.NewErrBadRequest(errors.Errorf("remotesource auth type required"))
	}

	// validate if the remotesource type supports the required auth type
	if !types.SourceSupportsAuthType(types.RemoteSourceType(remoteSource.Type), types.RemoteSourceAuthType(remoteSource.AuthType)) {
		return util.NewErrBadRequest(errors.Errorf("remotesource type %q doesn't support auth type %q", remoteSource.Type, remoteSource.AuthType))
	}
	if remoteSource.AuthType == types.RemoteSourceAuthTypeOauth2 {
		if remoteSource.Oauth2ClientID == "" {
			return util.NewErrBadRequest(errors.Errorf("remotesource oauth2clientid required for auth type %q", types.RemoteSourceAuthTypeOauth2))
		}
		if remoteSource.Oauth2ClientSecret == "" {
			return util.NewErrBadRequest(errors.Errorf("remotesource oauth2clientsecret required for auth type %q", types.RemoteSourceAuthTypeOauth2))
		}
	}

	return nil
}

func (h *ActionHandler) CreateRemoteSource(ctx context.Context, remoteSource *types.RemoteSource) (*types.RemoteSource, error) {
	if err := h.ValidateRemoteSource(ctx, remoteSource); err != nil {
		return nil, err
	}

	var cgt *datamanager.ChangeGroupsUpdateToken
	// changegroup is the remotesource name
	cgNames := []string{util.EncodeSha256Hex("remotesourcename-" + remoteSource.Name)}

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}

		// check duplicate remoteSource name
		u, err := h.readDB.GetRemoteSourceByName(tx, remoteSource.Name)
		if err != nil {
			return err
		}
		if u != nil {
			return util.NewErrBadRequest(errors.Errorf("remotesource %q already exists", u.Name))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	remoteSource.ID = uuid.NewV4().String()

	rsj, err := json.Marshal(remoteSource)
	if err != nil {
		return nil, errors.Errorf("failed to marshal remotesource: %w", err)
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
	return remoteSource, err
}

type UpdateRemoteSourceRequest struct {
	RemoteSourceRef string

	RemoteSource *types.RemoteSource
}

func (h *ActionHandler) UpdateRemoteSource(ctx context.Context, req *UpdateRemoteSourceRequest) (*types.RemoteSource, error) {
	if err := h.ValidateRemoteSource(ctx, req.RemoteSource); err != nil {
		return nil, err
	}

	var curRemoteSource *types.RemoteSource
	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error

		// check remotesource exists
		curRemoteSource, err = h.readDB.GetRemoteSourceByName(tx, req.RemoteSourceRef)
		if err != nil {
			return err
		}
		if curRemoteSource == nil {
			return util.NewErrBadRequest(errors.Errorf("remotesource with ref %q doesn't exist", req.RemoteSourceRef))
		}

		if curRemoteSource.Name != req.RemoteSource.Name {
			// check duplicate remoteSource name
			u, err := h.readDB.GetRemoteSourceByName(tx, req.RemoteSource.Name)
			if err != nil {
				return err
			}
			if u != nil {
				return util.NewErrBadRequest(errors.Errorf("remotesource %q already exists", u.Name))
			}
		}

		// set/override ID that must be kept from the current remote source
		req.RemoteSource.ID = curRemoteSource.ID

		// changegroup is the remotesource id and also name since we could change the
		// name so concurrently updating on the new name
		cgNames := []string{util.EncodeSha256Hex("remotesourcename-" + req.RemoteSource.Name), util.EncodeSha256Hex("remotesourceid-" + req.RemoteSource.ID)}
		cgt, err = h.readDB.GetChangeGroupsUpdateTokens(tx, cgNames)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	rsj, err := json.Marshal(req.RemoteSource)
	if err != nil {
		return nil, errors.Errorf("failed to marshal remotesource: %w", err)
	}
	actions := []*datamanager.Action{
		{
			ActionType: datamanager.ActionTypePut,
			DataType:   string(types.ConfigTypeRemoteSource),
			ID:         req.RemoteSource.ID,
			Data:       rsj,
		},
	}

	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return req.RemoteSource, err
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
			return err
		}
		if remoteSource == nil {
			return util.NewErrBadRequest(errors.Errorf("remotesource %q doesn't exist", remoteSourceName))
		}

		// changegroup is the remotesource id
		cgNames := []string{util.EncodeSha256Hex("remotesourceid-" + remoteSource.ID)}
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
			DataType:   string(types.ConfigTypeRemoteSource),
			ID:         remoteSource.ID,
		},
	}

	// changegroup is all the remotesources
	_, err = h.dm.WriteWal(ctx, actions, cgt)
	return err
}
