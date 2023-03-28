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
	"bufio"
	"context"
	"io"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/sorintlab/errors"
	"github.com/spf13/cobra"

	gatewayclient "agola.io/agola/services/gateway/client"
)

var cmdExport = &cobra.Command{
	Use: "export",
	Run: func(cmd *cobra.Command, args []string) {
		if err := export(cmd, args); err != nil {
			log.Fatal().Err(err).Send()
		}
	},
	Short: "export",
}

type exportOptions struct {
	outFilePath string
	servicename string
}

var exportOpts exportOptions

func init() {
	flags := cmdExport.Flags()

	flags.StringVar(&exportOpts.servicename, "service", "", "service name")
	flags.StringVar(&exportOpts.outFilePath, "out", "-", "output file path")

	cmdAgola.AddCommand(cmdExport)
}

func export(cmd *cobra.Command, args []string) error {
	gatewayclient := gatewayclient.NewClient(gatewayURL, token)

	resp, err := gatewayclient.Export(context.TODO(), exportOpts.servicename)
	if err != nil {
		return errors.WithStack(err)
	}

	var w *os.File
	if exportOpts.outFilePath == "-" {
		w = os.Stdout
	} else {
		var err error
		w, err = os.Create(exportOpts.outFilePath)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	r := bufio.NewReader(resp.Body)
	_, err = io.Copy(w, r)
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(err)
}
