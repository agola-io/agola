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

	"github.com/rs/zerolog/log"
	"github.com/sorintlab/errors"
	"github.com/spf13/cobra"

	migration248a9e0ad "agola.io/agola/internal/migration/248a9e0ad"
	migrationv07x "agola.io/agola/internal/migration/v0.7.x"
)

var cmdMigrateExport = &cobra.Command{
	Use:   "migrateexport",
	Short: "migrate from an old data format export to the new data format",
	Run: func(cmd *cobra.Command, args []string) {
		if err := migrateExport(cmd, args); err != nil {
			log.Fatal().Err(err).Send()
		}
	},
}

type migrateExportOptions struct {
	serviceName   string
	sourceVersion string
	inFilePath    string
	outFilePath   string
}

var migrateExportOpts migrateExportOptions

func init() {
	flags := cmdMigrateExport.Flags()

	flags.StringVar(&migrateExportOpts.serviceName, "service", "", "service name (runservice or configstore)")
	flags.StringVar(&migrateExportOpts.sourceVersion, "source-version", "v0.7.x", "export source version (v0.7.x or 248a9e0ad)")
	flags.StringVar(&migrateExportOpts.inFilePath, "in", "-", "input file path")
	flags.StringVar(&migrateExportOpts.outFilePath, "out", "-", "output file path")

	cmdAgola.AddCommand(cmdMigrateExport)
}

func migrateExport(cmd *cobra.Command, args []string) error {
	if migrateExportOpts.serviceName != "runservice" && migrateExportOpts.serviceName != "configstore" {
		return errors.Errorf("service option must be runservice or configstore")
	}
	if migrateExportOpts.sourceVersion != "v0.7.x" && migrateExportOpts.sourceVersion != "248a9e0ad" {
		return errors.Errorf("source version option must be v0.7.x or 248a9e0ad")
	}

	var r *os.File
	if migrateExportOpts.inFilePath == "-" {
		r = os.Stdin
	} else {
		var err error
		r, err = os.Open(migrateExportOpts.inFilePath)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	var w *os.File
	if migrateExportOpts.outFilePath == "-" {
		w = os.Stdout
	} else {
		var err error
		w, err = os.Create(migrateExportOpts.outFilePath)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	log.Info().Msgf("migrating export of service %s", migrateExportOpts.serviceName)
	switch migrateExportOpts.serviceName {
	case "runservice":
		switch migrateExportOpts.sourceVersion {
		case "v0.7.x":
			if err := migrationv07x.MigrateRunService(context.Background(), r, w); err != nil {
				return errors.WithStack(err)
			}
		case "248a9e0ad":
			if err := migration248a9e0ad.MigrateRunService(context.Background(), r, w); err != nil {
				return errors.WithStack(err)
			}
		}
	case "configstore":
		switch migrateExportOpts.sourceVersion {
		case "v0.7.x":
			if err := migrationv07x.MigrateConfigStore(context.Background(), r, w); err != nil {
				return errors.WithStack(err)
			}
		case "248a9e0ad":
			if err := migration248a9e0ad.MigrateConfigStore(context.Background(), r, w); err != nil {
				return errors.WithStack(err)
			}
		}
	}

	return nil
}
