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

	errors "golang.org/x/xerrors"
	"github.com/sorintlab/agola/internal/services/gateway/api"
	"github.com/sorintlab/agola/internal/services/types"

	"github.com/spf13/cobra"
)

var cmdOrgCreate = &cobra.Command{
	Use:   "create",
	Short: "create an organization",
	Run: func(cmd *cobra.Command, args []string) {
		if err := orgCreate(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type orgCreateOptions struct {
	name       string
	visibility string
}

var orgCreateOpts orgCreateOptions

func init() {
	flags := cmdOrgCreate.Flags()

	flags.StringVarP(&orgCreateOpts.name, "name", "n", "", "organization name")
	flags.StringVar(&orgCreateOpts.visibility, "visibility", "public", `organization visibility (public or private)`)

	cmdOrgCreate.MarkFlagRequired("name")

	cmdOrg.AddCommand(cmdOrgCreate)
}

func orgCreate(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	// TODO(sgotti) make this a custom pflag Value?
	if !types.IsValidVisibility(types.Visibility(orgCreateOpts.visibility)) {
		return errors.Errorf("invalid visibility %q", orgCreateOpts.visibility)
	}

	req := &api.CreateOrgRequest{
		Name:       orgCreateOpts.name,
		Visibility: types.Visibility(orgCreateOpts.visibility),
	}

	log.Infof("creating org")
	org, _, err := gwclient.CreateOrg(context.TODO(), req)
	if err != nil {
		return errors.Errorf("failed to create org: %w", err)
	}
	log.Infof("org %q created, ID: %q", org.Name, org.ID)

	return nil
}
