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

	"github.com/sorintlab/errors"

	serrors "agola.io/agola/internal/services/errors"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"
)

func (h *ActionHandler) GetRemoteSource(ctx context.Context, remoteSourceRef string) (*types.RemoteSource, error) {
	var remoteSource *types.RemoteSource
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		remoteSource, err = h.d.GetRemoteSource(tx, remoteSourceRef)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if remoteSource == nil {
		return nil, util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("remotesource %q doesn't exist", remoteSourceRef), serrors.RemoteSourceDoesNotExist())
	}

	return remoteSource, nil
}

type GetRemoteSourcesRequest struct {
	StartRemoteSourceName string

	Limit         int
	SortDirection types.SortDirection
}

type GetRemoteSourcesResponse struct {
	RemoteSources []*types.RemoteSource

	HasMore bool
}

func (h *ActionHandler) GetRemoteSources(ctx context.Context, req *GetRemoteSourcesRequest) (*GetRemoteSourcesResponse, error) {
	limit := req.Limit
	if limit > 0 {
		limit += 1
	}
	if req.SortDirection == "" {
		req.SortDirection = types.SortDirectionAsc
	}

	var remoteSources []*types.RemoteSource
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		remoteSources, err = h.d.GetRemoteSources(tx, req.StartRemoteSourceName, limit, req.SortDirection)
		return errors.WithStack(err)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var hasMore bool
	if req.Limit > 0 {
		hasMore = len(remoteSources) > req.Limit
		if hasMore {
			remoteSources = remoteSources[0:req.Limit]
		}
	}

	return &GetRemoteSourcesResponse{
		RemoteSources: remoteSources,
		HasMore:       hasMore,
	}, nil
}

func (h *ActionHandler) ValidateRemoteSourceReq(ctx context.Context, req *CreateUpdateRemoteSourceRequest) error {
	if req.Name == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("remotesource name required"), serrors.InvalidRemoteSourceName())
	}
	if !util.ValidateName(req.Name) {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("invalid remotesource name %q", req.Name), serrors.InvalidRemoteSourceName())
	}

	if req.APIURL == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("remotesource api url required"), serrors.InvalidRemoteSourceAPIURL())
	}
	if req.Type == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("remotesource type required"), serrors.InvalidRemoteSourceType())
	}
	if req.AuthType == "" {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("remotesource auth type required"), serrors.InvalidRemoteSourceAuthType())
	}

	// validate if the remotesource type supports the required auth type
	if !types.SourceSupportsAuthType(types.RemoteSourceType(req.Type), types.RemoteSourceAuthType(req.AuthType)) {
		return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("remotesource type %q doesn't support auth type %q", req.Type, req.AuthType), serrors.InvalidRemoteSourceAuthType())
	}
	if req.AuthType == types.RemoteSourceAuthTypeOauth2 {
		if req.Oauth2ClientID == "" {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("remotesource oauth2clientid required for auth type %q", types.RemoteSourceAuthTypeOauth2), serrors.InvalidOauth2ClientID())
		}
		if req.Oauth2ClientSecret == "" {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("remotesource oauth2clientsecret required for auth type %q", types.RemoteSourceAuthTypeOauth2), serrors.InvalidOauth2ClientSecret())
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
	RegistrationEnabled bool
	LoginEnabled        bool
}

func (h *ActionHandler) CreateRemoteSource(ctx context.Context, req *CreateUpdateRemoteSourceRequest) (*types.RemoteSource, error) {
	if err := h.ValidateRemoteSourceReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var remoteSource *types.RemoteSource
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		// check duplicate remoteSource name
		curRemoteSource, err := h.d.GetRemoteSourceByName(tx, req.Name)
		if err != nil {
			return errors.WithStack(err)
		}
		if curRemoteSource != nil {
			return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("remotesource %q already exists", req.Name), serrors.RemoteSourceAlreadyExists())
		}

		remoteSource = types.NewRemoteSource(tx)
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

		if err := h.d.InsertRemoteSource(tx, remoteSource); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return remoteSource, errors.WithStack(err)
}

func (h *ActionHandler) UpdateRemoteSource(ctx context.Context, remoteSourceRef string, req *CreateUpdateRemoteSourceRequest) (*types.RemoteSource, error) {
	if err := h.ValidateRemoteSourceReq(ctx, req); err != nil {
		return nil, errors.WithStack(err)
	}

	var remoteSource *types.RemoteSource
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		var err error

		// check remotesource exists
		remoteSource, err = h.d.GetRemoteSourceByName(tx, remoteSourceRef)
		if err != nil {
			return errors.WithStack(err)
		}
		if remoteSource == nil {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("remotesource with ref %q doesn't exist", remoteSourceRef), serrors.RemoteSourceDoesNotExist())
		}

		if remoteSource.Name != req.Name {
			// check duplicate remoteSource name
			u, err := h.d.GetRemoteSourceByName(tx, req.Name)
			if err != nil {
				return errors.WithStack(err)
			}
			if u != nil {
				return util.NewAPIError(util.ErrBadRequest, util.WithAPIErrorMsg("remotesource %q already exists", u.Name), serrors.RemoteSourceAlreadyExists())
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

		if err := h.d.UpdateRemoteSource(tx, remoteSource); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return remoteSource, errors.WithStack(err)
}

func (h *ActionHandler) DeleteRemoteSource(ctx context.Context, remoteSourceName string) error {
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		// check remoteSource existance
		remoteSource, err := h.d.GetRemoteSourceByName(tx, remoteSourceName)
		if err != nil {
			return errors.WithStack(err)
		}
		if remoteSource == nil {
			return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("remotesource %q doesn't exist", remoteSourceName), serrors.RemoteSourceDoesNotExist())
		}

		if err := h.d.DeleteRemoteSource(tx, remoteSource.ID); err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(err)
}

type GetLinkedAccountsRequest struct {
	QueryType string

	RemoteUserID   string
	RemoteSourceID string
}

func (h *ActionHandler) GetLinkedAccounts(ctx context.Context, req *GetLinkedAccountsRequest) ([]*types.LinkedAccount, error) {
	var linkedAccounts []*types.LinkedAccount
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		switch req.QueryType {
		case "byremoteuser":
			remoteUserID := req.RemoteUserID
			remoteSourceID := req.RemoteSourceID
			la, err := h.d.GetLinkedAccountByRemoteUserIDandSource(tx, remoteUserID, remoteSourceID)
			if err != nil {
				return errors.WithStack(err)
			}
			if la == nil {
				return util.NewAPIError(util.ErrNotExist, util.WithAPIErrorMsg("linked account with remote user %q for remote source %q token doesn't exist", remoteUserID, remoteSourceID), serrors.LinkedAccountDoesNotExist())
			}

			linkedAccounts = []*types.LinkedAccount{la}

		default:
			return errors.Errorf("unknown query_type: %q", req.QueryType)
		}

		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return linkedAccounts, nil
}
