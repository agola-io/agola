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
	stdsql "database/sql"
	"fmt"
	"io"
	"time"

	sq "github.com/huandu/go-sqlbuilder"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/services/configstore/db"
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/manager"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/util"
)

const (
	maintenanceTableName = "maintenance"
)

var (
	maintenanceTableDDL = fmt.Sprintf("create table if not exists %s (enabled boolean not null, time timestamptz not null)", maintenanceTableName)
)

func isMaintenanceEnabled(d *db.DB, tx *sql.Tx) (bool, error) {
	var enabled *bool
	sb := sq.Select("enabled").From(maintenanceTableName)
	q, args := sb.BuildWithFlavor(d.Flavor())
	if err := tx.QueryRow(q, args...).Scan(&enabled); err != nil && !errors.Is(err, stdsql.ErrNoRows) {
		return false, errors.Wrapf(err, "cannot get maintenance mode")
	}

	if enabled != nil && *enabled {
		return true, nil
	}

	return false, nil
}

func (h *ActionHandler) IsMaintenanceEnabled(ctx context.Context) (bool, error) {
	var enabled bool
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(maintenanceTableDDL); err != nil {
			return errors.Wrapf(err, "failed to create %s table", maintenanceTableName)
		}

		var err error
		enabled, err = isMaintenanceEnabled(h.d, tx)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return false, errors.WithStack(err)
	}

	return enabled, nil
}

func (h *ActionHandler) MaintenanceMode(ctx context.Context, enable bool) error {
	err := h.d.Do(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(maintenanceTableDDL); err != nil {
			return errors.Wrapf(err, "failed to create %s table", maintenanceTableName)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	err = h.d.Do(ctx, func(tx *sql.Tx) error {
		enabled, err := isMaintenanceEnabled(h.d, tx)
		if err != nil {
			return errors.WithStack(err)
		}

		if enable && enabled {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("maintenance mode already enabled"))
		}
		if !enable && !enabled {
			return util.NewAPIError(util.ErrBadRequest, errors.Errorf("maintenance mode already disabled"))
		}

		db := sq.DeleteFrom(maintenanceTableName)
		q, args := db.BuildWithFlavor(h.d.Flavor())
		if _, err := tx.Exec(q, args...); err != nil {
			return errors.Wrapf(err, "failed to update %s table", maintenanceTableName)
		}
		ib := sq.InsertInto(maintenanceTableName).Cols("enabled", "time").Values(enable, time.Now())
		q, args = ib.BuildWithFlavor(h.d.Flavor())
		if _, err := tx.Exec(q, args...); err != nil {
			return errors.Wrapf(err, "failed to update %s table", maintenanceTableName)
		}

		return nil
	})
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (h *ActionHandler) Export(ctx context.Context, w io.Writer) error {
	dbm := manager.NewDBManager(h.log, h.d, h.lf)
	return errors.WithStack(dbm.Export(ctx, sqlg.ObjectNames(h.d.ObjectsInfo()), w))
}

func (h *ActionHandler) Import(ctx context.Context, r io.Reader) error {
	if !h.maintenanceMode {
		return util.NewAPIError(util.ErrBadRequest, errors.Errorf("not in maintenance mode"))
	}

	dbm := manager.NewDBManager(h.log, h.d, h.lf)

	if err := dbm.Drop(ctx); err != nil {
		return errors.Wrap(err, "drop db error")
	}

	if err := dbm.Setup(ctx); err != nil {
		return errors.Wrap(err, "setup db error")
	}

	if err := dbm.Create(ctx, h.d.DDL(), h.d.Version()); err != nil {
		return errors.Wrap(err, "create db error")
	}

	if err := dbm.Import(ctx, r); err != nil {
		return errors.Wrap(err, "import db error")
	}

	return nil
}
