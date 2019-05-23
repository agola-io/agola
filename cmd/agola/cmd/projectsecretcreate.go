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
	"encoding/json"

	"github.com/sorintlab/agola/internal/services/gateway/api"
	"github.com/sorintlab/agola/internal/services/types"

	errors "golang.org/x/xerrors"
	"github.com/spf13/cobra"
)

var cmdProjectSecretCreate = &cobra.Command{
	Use:   "create",
	Short: "create a project secret",
	Run: func(cmd *cobra.Command, args []string) {
		if err := secretCreate(cmd, "project", args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type secretCreateOptions struct {
	parentRef string
	name      string
	data      string
}

var secretCreateOpts secretCreateOptions

func init() {
	flags := cmdProjectSecretCreate.Flags()

	flags.StringVar(&secretCreateOpts.parentRef, "project", "", "project id or full path)")
	flags.StringVarP(&secretCreateOpts.name, "name", "n", "", "secret name")
	flags.StringVar(&secretCreateOpts.data, "data", "", "json map of secret data")

	cmdProjectSecretCreate.MarkFlagRequired("project")
	cmdProjectSecretCreate.MarkFlagRequired("name")
	cmdProjectSecretCreate.MarkFlagRequired("data")

	cmdProjectSecret.AddCommand(cmdProjectSecretCreate)
}

func secretCreate(cmd *cobra.Command, ownertype string, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	var data map[string]string
	if err := json.Unmarshal([]byte(secretCreateOpts.data), &data); err != nil {
		log.Fatalf("failed to unmarshall values: %v", err)
	}
	req := &api.CreateSecretRequest{
		Name: secretCreateOpts.name,
		Type: types.SecretTypeInternal,
		Data: data,
	}

	switch ownertype {
	case "project":
		log.Infof("creating project secret")
		secret, _, err := gwclient.CreateProjectSecret(context.TODO(), secretCreateOpts.parentRef, req)
		if err != nil {
			return errors.Errorf("failed to create project secret: %w", err)
		}
		log.Infof("project secret %q created, ID: %q", secret.Name, secret.ID)
	case "projectgroup":
		log.Infof("creating project group secret")
		secret, _, err := gwclient.CreateProjectGroupSecret(context.TODO(), secretCreateOpts.parentRef, req)
		if err != nil {
			return errors.Errorf("failed to create project group secret: %w", err)
		}
		log.Infof("project group secret %q created, ID: %q", secret.Name, secret.ID)
	}

	return nil
}
