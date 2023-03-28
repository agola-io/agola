// Copyright 2022 Sorint.lab
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
	"io"
	"net/http"

	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/util"
)

const (
	ConfigstoreService = "configstore"
	RunserviceService  = "runservice"
)

type MaintenanceStatusResponse struct {
	RequestedStatus bool
	CurrentStatus   bool
}

func (h *ActionHandler) IsMaintenanceEnabled(ctx context.Context, serviceName string) (*MaintenanceStatusResponse, error) {
	if !common.IsUserAdmin(ctx) {
		return nil, util.NewAPIError(util.ErrUnauthorized, errors.Errorf("user not admin"))
	}

	switch serviceName {
	case ConfigstoreService:
		csresp, _, err := h.configstoreClient.GetMaintenanceStatus(ctx)
		if err != nil {
			return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
		}

		return &MaintenanceStatusResponse{RequestedStatus: csresp.RequestedStatus, CurrentStatus: csresp.CurrentStatus}, nil
	case RunserviceService:
		rsresp, _, err := h.runserviceClient.GetMaintenanceStatus(ctx)
		if err != nil {
			return nil, util.NewAPIError(util.KindFromRemoteError(err), err)
		}

		return &MaintenanceStatusResponse{RequestedStatus: rsresp.RequestedStatus, CurrentStatus: rsresp.CurrentStatus}, nil
	default:
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid service name %q", serviceName))
	}
}

func (h *ActionHandler) MaintenanceMode(ctx context.Context, serviceName string, enable bool) error {
	if !common.IsUserAdmin(ctx) {
		return util.NewAPIError(util.ErrUnauthorized, errors.Errorf("user not admin"))
	}

	var err error
	switch serviceName {
	case ConfigstoreService:
		if enable {
			_, err = h.configstoreClient.EnableMaintenance(ctx)
		} else {
			_, err = h.configstoreClient.DisableMaintenance(ctx)
		}
	case RunserviceService:
		if enable {
			_, err = h.runserviceClient.EnableMaintenance(ctx)
		} else {
			_, err = h.runserviceClient.DisableMaintenance(ctx)
		}
	default:
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid service name %q", serviceName))
	}

	if err != nil {
		return util.NewAPIError(util.KindFromRemoteError(err), err)
	}
	return nil
}

func (h *ActionHandler) Export(ctx context.Context, serviceName string) (*http.Response, error) {
	if !common.IsUserAdmin(ctx) {
		return nil, util.NewAPIError(util.ErrUnauthorized, errors.Errorf("user not admin"))
	}

	var err error
	var resp *http.Response
	switch serviceName {
	case ConfigstoreService:
		resp, err = h.configstoreClient.Export(ctx)
	case RunserviceService:
		resp, err = h.runserviceClient.Export(ctx)
	default:
		return nil, util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid service name %q", serviceName))
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return resp, nil
}

func (h *ActionHandler) Import(ctx context.Context, r io.Reader, serviceName string) error {
	if !common.IsUserAdmin(ctx) {
		return util.NewAPIError(util.ErrUnauthorized, errors.Errorf("user not admin"))
	}

	var err error
	switch serviceName {
	case ConfigstoreService:
		_, err = h.configstoreClient.Import(ctx, r)
	case RunserviceService:
		_, err = h.runserviceClient.Import(ctx, r)
	default:
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("invalid service name %q", serviceName))
	}
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
