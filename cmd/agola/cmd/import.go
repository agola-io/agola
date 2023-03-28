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

	gatewayclient "agola.io/agola/services/gateway/client"
)

var cmdImport = &cobra.Command{
	Use: "import",
	Run: func(cmd *cobra.Command, args []string) {
		if err := imp(cmd, args); err != nil {
			log.Fatal().Err(err).Send()
		}
	},
	Short: "import",
}

type importOptions struct {
	inFilePath  string
	servicename string
}

var importOpts importOptions

func init() {
	flags := cmdImport.Flags()

	flags.StringVar(&importOpts.servicename, "service", "", "service name")
	flags.StringVar(&importOpts.inFilePath, "in", "-", "input file path")

	cmdAgola.AddCommand(cmdImport)
}

func imp(cmd *cobra.Command, args []string) error {
	gatewayclient := gatewayclient.NewClient(gatewayURL, token)

	var r *os.File
	if importOpts.inFilePath == "-" {
		r = os.Stdin
	} else {
		var err error
		r, err = os.Open(importOpts.inFilePath)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	_, err := gatewayclient.Import(context.TODO(), importOpts.servicename, r)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
