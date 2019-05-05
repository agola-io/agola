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
