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

	"github.com/pkg/errors"
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
		return errors.Wrapf(err, "failed to create org")
	}
	log.Infof("org %q created, ID: %q", org.Name, org.ID)

	return nil
}
