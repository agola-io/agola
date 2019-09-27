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

var cmdProjectReconfig = &cobra.Command{
	Use:   "reconfig",
	Short: "reconfigures a project remote (reinstalls ssh deploy key and webhooks)",
	Run: func(cmd *cobra.Command, args []string) {
		if err := projectReconfig(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type projectReconfigOptions struct {
	name string
}

var projectReconfigOpts projectReconfigOptions

func init() {
	flags := cmdProjectReconfig.Flags()

	flags.StringVarP(&projectReconfigOpts.name, "name", "n", "", "project name")

	if err := cmdProjectReconfig.MarkFlagRequired("name"); err != nil {
		log.Fatal(err)
	}

	cmdProject.AddCommand(cmdProjectReconfig)
}

func projectReconfig(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	log.Infof("reconfiguring remote project")
	if _, err := gwclient.ReconfigProject(context.TODO(), projectReconfigOpts.name); err != nil {
		return errors.Errorf("failed to reconfigure remote project: %w", err)
	}
	log.Infof("project reconfigured")

	return nil
}
