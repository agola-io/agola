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

package cmd

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/sorintlab/errors"
	"github.com/spf13/cobra"

	"agola.io/agola/internal/services/config"
	csdb "agola.io/agola/internal/services/configstore/db"
	rsdb "agola.io/agola/internal/services/runservice/db"
	"agola.io/agola/internal/sqlg/lock"
	"agola.io/agola/internal/sqlg/manager"
	"agola.io/agola/internal/sqlg/sql"
)

var cmdMigrate = &cobra.Command{
	Use:   "migrate",
	Short: "migrate component database to latest version",
	Run: func(cmd *cobra.Command, args []string) {
		if err := migrate(cmd, args); err != nil {
			log.Fatal().Err(err).Send()
		}
	},
}

type migrateOptions struct {
	config      string
	serviceName string
}

var migrateOpts migrateOptions

func init() {
	flags := cmdMigrate.Flags()

	flags.StringVar(&migrateOpts.config, "config", "./config.yml", "config file path")
	flags.StringVar(&migrateOpts.serviceName, "service", "", "service name (runservice or configstore)")

	cmdAgola.AddCommand(cmdMigrate)
}

func migrate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	if migrateOpts.serviceName != "runservice" && migrateOpts.serviceName != "configstore" {
		return errors.Errorf("service option must be runservice or configstore")
	}

	components := []string{migrateOpts.serviceName}

	c, err := config.Parse(migrateOpts.config, components)
	if err != nil {
		return errors.Wrapf(err, "config error")
	}

	var sdb *sql.DB
	var d manager.DB
	switch migrateOpts.serviceName {
	case "runservice":
		var err error

		dbConf := c.Runservice.DB

		sdb, err = sql.NewDB(dbConf.Type, dbConf.ConnString)
		if err != nil {
			return errors.Wrapf(err, "new db error")
		}

		d, err = rsdb.NewDB(log.Logger, sdb)
		if err != nil {
			return errors.Wrapf(err, "new db error")
		}

	case "configstore":
		var err error

		dbConf := c.Configstore.DB

		sdb, err = sql.NewDB(dbConf.Type, dbConf.ConnString)
		if err != nil {
			return errors.Wrapf(err, "new db error")
		}

		d, err = csdb.NewDB(log.Logger, sdb)
		if err != nil {
			return errors.Wrapf(err, "new db error")
		}
	}

	var lf lock.LockFactory
	switch d.DBType() {
	case sql.Sqlite3:
		ll := lock.NewLocalLocks()
		lf = lock.NewLocalLockFactory(ll)
	case sql.Postgres:
		lf = lock.NewPGLockFactory(sdb)
	default:
		return errors.Errorf("unknown db type %q", d.DBType())
	}

	dbm := manager.NewDBManager(log.Logger, d, lf)

	log.Info().Msgf("migrating service %s", migrateOpts.serviceName)

	curDBVersion, err := dbm.GetVersion(ctx)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := dbm.CheckVersion(curDBVersion, d.Version()); err != nil {
		return errors.WithStack(err)
	}

	migrationRequired, err := dbm.CheckMigrationRequired(curDBVersion, d.Version())
	if err != nil {
		return errors.WithStack(err)
	}
	if !migrationRequired {
		log.Info().Msgf("db already at latest version: %d", curDBVersion)
		return nil
	}

	if err := dbm.Migrate(ctx); err != nil {
		return errors.Wrap(err, "migrate db error")
	}

	log.Info().Msgf("db migrated to version: %d", d.Version())

	return nil
}
