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

	gatewayclient "agola.io/agola/services/gateway/client"
)

var cmdMaintenanceDisable = &cobra.Command{
	Use: "disable",
	Run: func(cmd *cobra.Command, args []string) {
		if err := disable(cmd, args); err != nil {
			log.Fatal().Err(err).Send()
		}
	},
	Short: "disable",
}

func init() {
	cmdMaintenance.AddCommand(cmdMaintenanceDisable)
}

func disable(cmd *cobra.Command, args []string) error {
	gatewayclient := gatewayclient.NewClient(gatewayURL, token)

	_, err := gatewayclient.DisableMaintenance(context.TODO(), maintenanceOpts.servicename)

	return errors.WithStack(err)
}
