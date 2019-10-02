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

var cmdProjectGroupDelete = &cobra.Command{
	Use:   "delete",
	Short: "delete a project group",
	Run: func(cmd *cobra.Command, args []string) {
		if err := projectGroupDelete(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type projectGroupDeleteOptions struct {
	ref string
}

var projectGroupDeleteOpts projectGroupDeleteOptions

func init() {
	flags := cmdProjectGroupDelete.Flags()

	flags.StringVarP(&projectGroupDeleteOpts.ref, "ref", "", "", "current project group path or id")

	if err := cmdProjectGroupDelete.MarkFlagRequired("ref"); err != nil {
		log.Fatal(err)
	}

	cmdProjectGroup.AddCommand(cmdProjectGroupDelete)
}

func projectGroupDelete(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	log.Infof("deleting project group")

	if _, err := gwclient.DeleteProjectGroup(context.TODO(), projectGroupDeleteOpts.ref); err != nil {
		return errors.Errorf("failed to delete project group: %w", err)
	}

	return nil
}
