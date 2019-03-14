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
	"net/url"

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/services/gateway/api"
	"github.com/spf13/cobra"
)

var cmdProjectSecretCreate = &cobra.Command{
	Use:   "create",
	Short: "create a project secret",
	Run: func(cmd *cobra.Command, args []string) {
		if err := projectSecretCreate(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type projectSecretCreateOptions struct {
	projectID string
	name      string
}

var projectSecretCreateOpts projectSecretCreateOptions

func init() {
	flags := cmdProjectSecretCreate.Flags()

	flags.StringVar(&projectSecretCreateOpts.projectID, "project", "", "project id or full path)")
	flags.StringVarP(&projectSecretCreateOpts.name, "name", "n", "", "secret name")

	cmdProjectSecretCreate.MarkFlagRequired("project")
	cmdProjectSecretCreate.MarkFlagRequired("name")

	cmdProjectSecret.AddCommand(cmdProjectSecretCreate)
}

func projectSecretCreate(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	req := &api.CreateSecretRequest{
		Name: projectSecretCreateOpts.name,
	}

	log.Infof("creating project secret")
	secret, _, err := gwclient.CreateProjectSecret(context.TODO(), url.PathEscape(projectSecretCreateOpts.projectID), req)
	if err != nil {
		return errors.Wrapf(err, "failed to create project secret")
	}
	log.Infof("project secret %q created, ID: %q", secret.Name, secret.ID)

	return nil
}
