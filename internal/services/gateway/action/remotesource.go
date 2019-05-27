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

	errors "golang.org/x/xerrors"
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
	Name                string
	APIURL              string
	SkipVerify          bool
	Type                string
	AuthType            string
	Oauth2ClientID      string
	Oauth2ClientSecret  string
	SSHHostKey          string
	SkipSSHHostKeyCheck bool
}

func (h *ActionHandler) CreateRemoteSource(ctx context.Context, req *CreateRemoteSourceRequest) (*types.RemoteSource, error) {
	if !h.IsUserAdmin(ctx) {
		return nil, errors.Errorf("user not admin")
	}

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
		Name:                req.Name,
		Type:                types.RemoteSourceType(req.Type),
		AuthType:            types.RemoteSourceAuthType(req.AuthType),
		APIURL:              req.APIURL,
		SkipVerify:          req.SkipVerify,
		Oauth2ClientID:      req.Oauth2ClientID,
		Oauth2ClientSecret:  req.Oauth2ClientSecret,
		SSHHostKey:          req.SSHHostKey,
		SkipSSHHostKeyCheck: req.SkipSSHHostKeyCheck,
	}

	h.log.Infof("creating remotesource")
	rs, resp, err := h.configstoreClient.CreateRemoteSource(ctx, rs)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Errorf("failed to create remotesource: %w", err))
	}
	h.log.Infof("remotesource %s created, ID: %s", rs.Name, rs.ID)

	return rs, nil
}

type UpdateRemoteSourceRequest struct {
	RemoteSourceRef string

	Name                *string
	APIURL              *string
	SkipVerify          *bool
	Oauth2ClientID      *string
	Oauth2ClientSecret  *string
	SSHHostKey          *string
	SkipSSHHostKeyCheck *bool
}

func (h *ActionHandler) UpdateRemoteSource(ctx context.Context, req *UpdateRemoteSourceRequest) (*types.RemoteSource, error) {
	if !h.IsUserAdmin(ctx) {
		return nil, errors.Errorf("user not admin")
	}

	rs, resp, err := h.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceRef)
	if err != nil {
		return nil, ErrFromRemote(resp, err)
	}

	if req.Name != nil {
		rs.Name = *req.Name
	}
	if req.APIURL != nil {
		rs.APIURL = *req.APIURL
	}
	if req.SkipVerify != nil {
		rs.SkipVerify = *req.SkipVerify
	}
	if req.Oauth2ClientID != nil {
		rs.Oauth2ClientID = *req.Oauth2ClientID
	}
	if req.Oauth2ClientSecret != nil {
		rs.Oauth2ClientSecret = *req.Oauth2ClientSecret
	}
	if req.SSHHostKey != nil {
		rs.SSHHostKey = *req.SSHHostKey
	}
	if req.SkipSSHHostKeyCheck != nil {
		rs.SkipSSHHostKeyCheck = *req.SkipSSHHostKeyCheck
	}

	h.log.Infof("updating remotesource")
	rs, resp, err = h.configstoreClient.UpdateRemoteSource(ctx, req.RemoteSourceRef, rs)
	if err != nil {
		return nil, ErrFromRemote(resp, errors.Errorf("failed to update remotesource: %w", err))
	}
	h.log.Infof("remotesource %s updated", rs.Name)

	return rs, nil
}

func (h *ActionHandler) DeleteRemoteSource(ctx context.Context, rsRef string) error {
	if !h.IsUserAdmin(ctx) {
		return errors.Errorf("user not admin")
	}

	resp, err := h.configstoreClient.DeleteRemoteSource(ctx, rsRef)
	if err != nil {
		return ErrFromRemote(resp, errors.Errorf("failed to delete remote source: %w", err))
	}
	return nil
}
