// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"

	"github.com/sorintlab/agola/internal/services/gateway/api"

	errors "golang.org/x/xerrors"
	"github.com/spf13/cobra"
)

var cmdProjectSecretDelete = &cobra.Command{
	Use:   "delete",
	Short: "delete a secret",
	Run: func(cmd *cobra.Command, args []string) {
		if err := secretDelete(cmd, "project", args); err != nil {
			log.Fatalf("err: %v", err)
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

	flags.StringVar(&secretDeleteOpts.parentRef, "project", "", "project id or full path)")
	flags.StringVarP(&secretDeleteOpts.name, "name", "n", "", "secret name")

	cmdProjectSecretDelete.MarkFlagRequired("projectgroup")
	cmdProjectSecretDelete.MarkFlagRequired("name")

	cmdProjectSecret.AddCommand(cmdProjectSecretDelete)
}

func secretDelete(cmd *cobra.Command, ownertype string, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	switch ownertype {
	case "project":
		log.Infof("deleting project secret")
		_, err := gwclient.DeleteProjectSecret(context.TODO(), secretDeleteOpts.parentRef, secretDeleteOpts.name)
		if err != nil {
			return errors.Errorf("failed to delete project secret: %w", err)
		}
		log.Infof("project secret deleted")
	case "projectgroup":
		log.Infof("deleting project group secret")
		_, err := gwclient.DeleteProjectGroupSecret(context.TODO(), secretDeleteOpts.parentRef, secretDeleteOpts.name)
		if err != nil {
			return errors.Errorf("failed to delete project group secret: %w", err)
		}
		log.Infof("project group secret deleted")
	}

	return nil
}
