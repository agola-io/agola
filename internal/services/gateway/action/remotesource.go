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

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"
)

func (h *ActionHandler) GetRemoteSource(ctx context.Context, rsRef string) (*cstypes.RemoteSource, error) {
	rs, _, err := h.configstoreClient.GetRemoteSource(ctx, rsRef)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return rs, nil
}

type GetRemoteSourcesRequest struct {
	Start string
	Limit int
	Asc   bool
}

func (h *ActionHandler) GetRemoteSources(ctx context.Context, req *GetRemoteSourcesRequest) ([]*cstypes.RemoteSource, error) {
	remoteSources, _, err := h.configstoreClient.GetRemoteSources(ctx, req.Start, req.Limit, req.Asc)
	if err != nil {
		return nil, errors.WithStack(err)
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
	RegistrationEnabled *bool
	LoginEnabled        *bool
}

func (h *ActionHandler) CreateRemoteSource(ctx context.Context, req *CreateRemoteSourceRequest) (*cstypes.RemoteSource, error) {
	if !common.IsUserAdmin(ctx) {
		return nil, errors.Errorf("user not admin")
	}

	if !util.ValidateName(req.Name) {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid remotesource name %q", req.Name))
	}

	if req.Name == "" {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource name required"))
	}
	if req.APIURL == "" {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource api url required"))
	}
	if req.Type == "" {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource type required"))
	}
	if req.AuthType == "" {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource auth type required"))
	}

	// validate if the remote source type supports the required auth type
	if !cstypes.SourceSupportsAuthType(cstypes.RemoteSourceType(req.Type), cstypes.RemoteSourceAuthType(req.AuthType)) {
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource type %q doesn't support auth type %q", req.Type, req.AuthType))
	}

	if req.AuthType == string(cstypes.RemoteSourceAuthTypeOauth2) {
		if req.Oauth2ClientID == "" {
			return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource oauth2 clientid required"))
		}
		if req.Oauth2ClientSecret == "" {
			return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("remotesource oauth2 client secret required"))
		}
	}

	creq := &csapitypes.CreateUpdateRemoteSourceRequest{
		Name:                req.Name,
		Type:                cstypes.RemoteSourceType(req.Type),
		AuthType:            cstypes.RemoteSourceAuthType(req.AuthType),
		APIURL:              req.APIURL,
		SkipVerify:          req.SkipVerify,
		Oauth2ClientID:      req.Oauth2ClientID,
		Oauth2ClientSecret:  req.Oauth2ClientSecret,
		SSHHostKey:          req.SSHHostKey,
		SkipSSHHostKeyCheck: req.SkipSSHHostKeyCheck,
		RegistrationEnabled: req.RegistrationEnabled,
		LoginEnabled:        req.LoginEnabled,
	}

	h.log.Info().Msgf("creating remotesource")
	rs, _, err := h.configstoreClient.CreateRemoteSource(ctx, creq)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create remotesource")
	}
	h.log.Info().Msgf("remotesource %s created, ID: %s", rs.Name, rs.ID)

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
	RegistrationEnabled *bool
	LoginEnabled        *bool
}

func (h *ActionHandler) UpdateRemoteSource(ctx context.Context, req *UpdateRemoteSourceRequest) (*cstypes.RemoteSource, error) {
	if !common.IsUserAdmin(ctx) {
		return nil, errors.Errorf("user not admin")
	}

	rs, _, err := h.configstoreClient.GetRemoteSource(ctx, req.RemoteSourceRef)
	if err != nil {
		return nil, errors.WithStack(err)
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
	if req.RegistrationEnabled != nil {
		rs.RegistrationEnabled = req.RegistrationEnabled
	}
	if req.LoginEnabled != nil {
		rs.LoginEnabled = req.LoginEnabled
	}

	creq := &csapitypes.CreateUpdateRemoteSourceRequest{
		Name:                rs.Name,
		Type:                rs.Type,
		AuthType:            rs.AuthType,
		APIURL:              rs.APIURL,
		SkipVerify:          rs.SkipVerify,
		Oauth2ClientID:      rs.Oauth2ClientID,
		Oauth2ClientSecret:  rs.Oauth2ClientSecret,
		SSHHostKey:          rs.SSHHostKey,
		SkipSSHHostKeyCheck: rs.SkipSSHHostKeyCheck,
		RegistrationEnabled: rs.RegistrationEnabled,
		LoginEnabled:        rs.LoginEnabled,
	}

	h.log.Info().Msgf("updating remotesource")
	rs, _, err = h.configstoreClient.UpdateRemoteSource(ctx, req.RemoteSourceRef, creq)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to update remotesource")
	}
	h.log.Info().Msgf("remotesource %s updated", rs.Name)

	return rs, nil
}

func (h *ActionHandler) DeleteRemoteSource(ctx context.Context, rsRef string) error {
	if !common.IsUserAdmin(ctx) {
		return errors.Errorf("user not admin")
	}

	if _, err := h.configstoreClient.DeleteRemoteSource(ctx, rsRef); err != nil {
		return errors.Wrapf(err, "failed to delete remote source")
	}
	return nil
}
