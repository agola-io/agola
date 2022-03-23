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
	"os"

	"agola.io/agola/internal/errors"
	"agola.io/agola/internal/migration"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var cmdMigrate = &cobra.Command{
	Use:   "migrate",
	Short: "migrate from an old data format export to the new data format",
	Run: func(cmd *cobra.Command, args []string) {
		if err := migrate(cmd, args); err != nil {
			log.Fatal().Err(err).Send()
		}
	},
}

type migrateOptions struct {
	serviceName string
	inFilePath  string
	outFilePath string
}

var migrateOpts migrateOptions

func init() {
	flags := cmdMigrate.Flags()

	flags.StringVar(&migrateOpts.serviceName, "service", "", "service name (runservice or configstore)")
	flags.StringVar(&migrateOpts.inFilePath, "in", "-", "input file path")
	flags.StringVar(&migrateOpts.outFilePath, "out", "-", "output file path")

	cmdAgola.AddCommand(cmdMigrate)
}

func migrate(cmd *cobra.Command, args []string) error {
	if migrateOpts.serviceName != "runservice" && migrateOpts.serviceName != "configstore" {
		return errors.Errorf("service option must be runservice or configstore")
	}

	var r *os.File
	if migrateOpts.inFilePath == "-" {
		r = os.Stdin
	} else {
		var err error
		r, err = os.Open(migrateOpts.inFilePath)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	var w *os.File
	if migrateOpts.outFilePath == "-" {
		w = os.Stdout
	} else {
		var err error
		w, err = os.Create(migrateOpts.outFilePath)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	log.Info().Msgf("migrating %s", migrateOpts.serviceName)
	switch migrateOpts.serviceName {
	case "runservice":
		if err := migration.MigrateRunService(context.Background(), r, w); err != nil {
			return errors.WithStack(err)
		}
	case "configstore":
		if err := migration.MigrateConfigStore(context.Background(), r, w); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}
