package migration

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"github.com/sorintlab/errors"

	dbv1 "agola.io/agola/internal/migration/destination/configstore/db"
	"agola.io/agola/internal/services/configstore/db"
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/lock"
	"agola.io/agola/internal/sqlg/manager"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/services/configstore/types"
)

func MigrateConfigStore(ctx context.Context, r io.Reader, w io.Writer) error {
	ll := lock.NewLocalLocks()
	lf := lock.NewLocalLockFactory(ll)

	dir, err := os.MkdirTemp("", "agolamigration")
	if err != nil {
		return errors.Wrap(err, "new db error")
	}
	dbPath := filepath.Join(dir, "newdb")
	os.RemoveAll(dbPath)

	sdb, err := sql.NewDB(sql.Sqlite3, dbPath)
	if err != nil {
		return errors.Wrap(err, "new db error")
	}
	defer sdb.Close()

	// Use a copy of db at version 1
	dv1, err := dbv1.NewDB(log.Logger, sdb)
	if err != nil {
		return errors.Wrap(err, "new db error")
	}

	dbmv1 := manager.NewDBManager(log.Logger, dv1, lf)

	if err := dbmv1.Setup(ctx); err != nil {
		return errors.Wrap(err, "setup db error")
	}

	if err := dbmv1.Create(ctx, dv1.DDL(), dv1.Version()); err != nil {
		return errors.Wrap(err, "create db error")
	}

	br := bufio.NewReader(r)
	dec := json.NewDecoder(br)

	tx, err := sdb.NewTx(ctx)
	if err != nil {
		return errors.WithStack(err)
	}

	if _, err := tx.Exec("PRAGMA defer_foreign_keys = ON"); err != nil {
		return errors.WithStack(err)
	}

	for {
		var data json.RawMessage

		err := dec.Decode(&data)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.WithStack(err)
		}

		var om exportObjectExportMeta
		if err := json.Unmarshal(data, &om); err != nil {
			return errors.WithStack(err)
		}

		var obj sqlg.Object

		switch om.Kind {
		case "remotesource":
			obj = &types.RemoteSource{}
		case "user":
			obj = &types.User{}
		case "usertoken":
			obj = &types.UserToken{}
		case "linkedaccount":
			obj = &types.LinkedAccount{}
		case "organization":
			obj = &types.Organization{}
		case "organizationmember":
			obj = &types.OrganizationMember{}
		case "projectgroup":
			obj = &types.ProjectGroup{}
		case "project":
			obj = &types.Project{}
		case "secret":
			obj = &types.Secret{}
		case "variable":
			obj = &types.Variable{}
		case "orginvitation":
			obj = &types.OrgInvitation{}

		default:
			panic(errors.Errorf("unknown object kind %q, data: %s", om.Kind, data))
		}

		switch o := obj.(type) {
		case *types.RemoteSource:
			type remoteSourceChangedData struct {
				RegistrationEnabled *bool `json:"registration_enabled,omitempty"`
				LoginEnabled        *bool `json:"login_enabled,omitempty"`
			}
			rscd := &remoteSourceChangedData{}
			if err := json.Unmarshal(data, &rscd); err != nil {
				return errors.WithStack(err)
			}

			if err := json.Unmarshal(data, &obj); err != nil {
				return errors.WithStack(err)
			}

			o.RegistrationEnabled = true
			if rscd.RegistrationEnabled != nil {
				o.RegistrationEnabled = *rscd.RegistrationEnabled
			}
			o.LoginEnabled = true
			if rscd.LoginEnabled != nil {
				o.LoginEnabled = *rscd.LoginEnabled
			}

		case *types.OrgInvitation:
			type oldOrgInvitation struct {
				UserID         string           `json:"userId,omitempty"`
				OrganizationID string           `json:"organizationId,omitempty"`
				Role           types.MemberRole `json:"role,omitempty"`
			}
			ooi := &oldOrgInvitation{}
			if err := json.Unmarshal(data, &ooi); err != nil {
				return errors.WithStack(err)
			}

			if err := json.Unmarshal(data, &obj); err != nil {
				return errors.WithStack(err)
			}

			o.UserID = ooi.UserID
			o.OrganizationID = ooi.OrganizationID

		default:
			if err := json.Unmarshal(data, &obj); err != nil {
				return errors.WithStack(err)
			}
		}

		if err := dv1.InsertRawObject(tx, obj); err != nil {
			return errors.WithStack(err)
		}

	}

	if err := tx.Commit(); err != nil {
		return errors.WithStack(err)
	}

	// Migrate to latest version
	d, err := db.NewDB(log.Logger, sdb)
	if err != nil {
		return errors.Wrap(err, "new db error")
	}

	dbm := manager.NewDBManager(log.Logger, d, lf)

	if err := dbm.Setup(ctx); err != nil {
		return errors.Wrap(err, "setup db error")
	}

	if err := dbm.Migrate(ctx); err != nil {
		return errors.Wrap(err, "migrate db error")
	}

	// Export new version
	if err := dbm.Export(ctx, sqlg.ObjectNames(d.ObjectsInfo()), w); err != nil {
		return errors.Wrap(err, "export db error")
	}

	return nil
}
