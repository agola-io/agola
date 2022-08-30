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

package cmd

import (
	"context"

	"agola.io/agola/internal/errors"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var cmdProjectSecretDelete = &cobra.Command{
	Use:   "delete",
	Short: "delete a secret",
	Run: func(cmd *cobra.Command, args []string) {
		if err := secretDelete(cmd, "project", args); err != nil {
			log.Fatal().Err(err).Send()
		}
	},
}

type secretDeleteOptions struct {
	parentRef string
	name      string
}

var secretDeleteOpts secretDeleteOptions

func init() {
	flags := cmdProjectSecretDelete.Flags()

	flags.StringVar(&secretDeleteOpts.parentRef, "project", "", "project id or full path")
	flags.StringVarP(&secretDeleteOpts.name, "name", "n", "", "secret name")

	if err := cmdProjectSecretDelete.MarkFlagRequired("project"); err != nil {
		log.Fatal().Err(err).Send()
	}
	if err := cmdProjectSecretDelete.MarkFlagRequired("name"); err != nil {
		log.Fatal().Err(err).Send()
	}

	cmdProjectSecret.AddCommand(cmdProjectSecretDelete)
}

func secretDelete(cmd *cobra.Command, ownertype string, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	switch ownertype {
	case "project":
		log.Info().Msgf("deleting project secret")
		_, err := gwclient.DeleteProjectSecret(context.TODO(), secretDeleteOpts.parentRef, secretDeleteOpts.name)
		if err != nil {
			return errors.Wrapf(err, "failed to delete project secret")
		}
		log.Info().Msgf("project secret deleted")
	case "projectgroup":
		log.Info().Msgf("deleting project group secret")
		_, err := gwclient.DeleteProjectGroupSecret(context.TODO(), secretDeleteOpts.parentRef, secretDeleteOpts.name)
		if err != nil {
			return errors.Wrapf(err, "failed to delete project group secret")
		}
		log.Info().Msgf("project group secret deleted")
	}

	return nil
}
