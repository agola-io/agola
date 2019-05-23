// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package action

import (
	"context"
	"encoding/json"

	"github.com/sorintlab/agola/internal/datamanager"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	errors "golang.org/x/xerrors"
	uuid "github.com/satori/go.uuid"
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
	err := h.readDB.Do(func(tx *db.Tx) error {
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

	var cgt *datamanager.ChangeGroupsUpdateToken

	// must do all the checks in a single transaction to avoid concurrent changes
	err := h.readDB.Do(func(tx *db.Tx) error {
		var err error
		// check duplicate remoteSource name
		curRemoteSource, err := h.readDB.GetRemoteSourceByName(tx, req.RemoteSourceRef)
		if err != nil {
			return err
		}
		if curRemoteSource == nil {
			return util.NewErrBadRequest(errors.Errorf("remotesource with ref %q doesn't exist", req.RemoteSourceRef))
		}

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
	err := h.readDB.Do(func(tx *db.Tx) error {
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
