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

	gwclient "agola.io/agola/services/gateway/client"

	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
)

var cmdOrgDelete = &cobra.Command{
	Use:   "delete",
	Short: "delete an organization",
	Run: func(cmd *cobra.Command, args []string) {
		if err := orgDelete(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type orgDeleteOptions struct {
	name string
}

var orgDeleteOpts orgDeleteOptions

func init() {
	flags := cmdOrgDelete.Flags()

	flags.StringVarP(&orgDeleteOpts.name, "name", "n", "", "organization name")

	if err := cmdOrgDelete.MarkFlagRequired("name"); err != nil {
		log.Fatal(err)
	}

	cmdOrg.AddCommand(cmdOrgDelete)
}

func orgDelete(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	log.Infof("deleting organization %q", orgDeleteOpts.name)
	if _, err := gwclient.DeleteOrg(context.TODO(), orgDeleteOpts.name); err != nil {
		return errors.Errorf("failed to delete organization: %w", err)
	}

	return nil
}
