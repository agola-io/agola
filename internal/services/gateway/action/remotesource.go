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

	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/pkg/errors"
)

func (h *ActionHandler) GetRemoteSource(ctx context.Context, rsRef string) (*types.RemoteSource, error) {
	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, rsRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	return rs, nil
}

type GetRemoteSourcesRequest struct {
	Start string
	Limit int
	Asc   bool
}

func (h *ActionHandler) GetRemoteSources(ctx context.Context, req *GetRemoteSourcesRequest) ([]*types.RemoteSource, error) {
	remoteSources, resp, err := h.configstoreClient.GetRemoteSources(ctx, req.Start, req.Limit, req.Asc)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}
	return remoteSources, nil
}

type CreateRemoteSourceRequest struct {
	Name               string
	APIURL             string
	Type               string
	AuthType           string
	Oauth2ClientID     string
	Oauth2ClientSecret string
}

func (h *ActionHandler) CreateRemoteSource(ctx context.Context, req *CreateRemoteSourceRequest) (*types.RemoteSource, error) {
	if !util.ValidateName(req.Name) {
		return nil, util.NewErrBadRequest(errors.Errorf("invalid remotesource name %q", req.Name))
	}

	if req.Name == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("remotesource name required"))
	}
	if req.APIURL == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("remotesource api url required"))
	}
	if req.Type == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("remotesource type required"))
	}
	if req.AuthType == "" {
		return nil, util.NewErrBadRequest(errors.Errorf("remotesource auth type required"))
	}

	// validate if the remote source type supports the required auth type
	if !types.SourceSupportsAuthType(types.RemoteSourceType(req.Type), types.RemoteSourceAuthType(req.AuthType)) {
		return nil, util.NewErrBadRequest(errors.Errorf("remotesource type %q doesn't support auth type %q", req.Type, req.AuthType))
	}

	if req.AuthType == string(types.RemoteSourceAuthTypeOauth2) {
		if req.Oauth2ClientID == "" {
			return nil, util.NewErrBadRequest(errors.Errorf("remotesource oauth2 clientid required"))
		}
		if req.Oauth2ClientSecret == "" {
			return nil, util.NewErrBadRequest(errors.Errorf("remotesource oauth2 client secret required"))
		}
	}

	rs := &types.RemoteSource{
		Name:               req.Name,
		Type:               types.RemoteSourceType(req.Type),
		AuthType:           types.RemoteSourceAuthType(req.AuthType),
		APIURL:             req.APIURL,
		Oauth2ClientID:     req.Oauth2ClientID,
		Oauth2ClientSecret: req.Oauth2ClientSecret,
	}

	h.log.Infof("creating remotesource")
	rs, resp, err := h.configstoreClient.CreateRemoteSource(ctx, rs)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Wrapf(err, "failed to create remotesource"))
	}
	h.log.Infof("remotesource %s created, ID: %s", rs.Name, rs.ID)

	return rs, nil
}

func (h *ActionHandler) DeleteRemoteSource(ctx context.Context, rsRef string) error {
	resp, err := h.configstoreClient.DeleteRemoteSource(ctx, rsRef)
	if err != nil {
		return ErrFromRemote(resp, errors.Wrapf(err, "failed to delete remote source"))
	}
	return nil
}
