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
	"io"

	"agola.io/agola/internal/etcd"
	"agola.io/agola/internal/services/configstore/common"
	"agola.io/agola/internal/util"

	errors "golang.org/x/xerrors"
)

func (h *ActionHandler) MaintenanceMode(ctx context.Context, enable bool) error {
	resp, err := h.e.Get(ctx, common.EtcdMaintenanceKey, 0)
	if err != nil && err != etcd.ErrKeyNotFound {
		return err
	}

	if enable && len(resp.Kvs) > 0 {
		return util.NewErrBadRequest(errors.Errorf("maintenance mode already enabled"))
	}
	if !enable && len(resp.Kvs) == 0 {
		return util.NewErrBadRequest(errors.Errorf("maintenance mode already disabled"))
	}

	if enable {
		txResp, err := h.e.AtomicPut(ctx, common.EtcdMaintenanceKey, []byte{}, 0, nil)
		if err != nil {
			return err
		}
		if !txResp.Succeeded {
			return errors.Errorf("failed to create maintenance mode key due to concurrent update")
		}
	}

	if !enable {
		txResp, err := h.e.AtomicDelete(ctx, common.EtcdMaintenanceKey, resp.Kvs[0].ModRevision)
		if err != nil {
			return err
		}
		if !txResp.Succeeded {
			return errors.Errorf("failed to delete maintenance mode key due to concurrent update")
		}
	}

	return nil
}

func (h *ActionHandler) Export(ctx context.Context, w io.Writer) error {
	return h.dm.Export(ctx, w)
}

func (h *ActionHandler) Import(ctx context.Context, r io.Reader) error {
	if !h.maintenanceMode {
		return util.NewErrBadRequest(errors.Errorf("not in maintenance mode"))
	}
	return h.dm.Import(ctx, r)
}
