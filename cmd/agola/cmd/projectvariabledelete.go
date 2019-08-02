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

var cmdProjectVariableDelete = &cobra.Command{
	Use:   "delete",
	Short: "delete a variable",
	Run: func(cmd *cobra.Command, args []string) {
		if err := variableDelete(cmd, "project", args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type variableDeleteOptions struct {
	parentRef string
	name      string
}

var variableDeleteOpts variableDeleteOptions

func init() {
	flags := cmdProjectVariableDelete.Flags()

	flags.StringVar(&variableDeleteOpts.parentRef, "project", "", "project id or full path")
	flags.StringVarP(&variableDeleteOpts.name, "name", "n", "", "variable name")

	if err := cmdProjectVariableDelete.MarkFlagRequired("project"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectVariableDelete.MarkFlagRequired("name"); err != nil {
		log.Fatal(err)
	}

	cmdProjectVariable.AddCommand(cmdProjectVariableDelete)
}

func variableDelete(cmd *cobra.Command, ownertype string, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	switch ownertype {
	case "project":
		log.Infof("deleting project variable")
		_, err := gwclient.DeleteProjectVariable(context.TODO(), variableDeleteOpts.parentRef, variableDeleteOpts.name)
		if err != nil {
			return errors.Errorf("failed to delete project variable: %w", err)
		}
		log.Infof("project variable deleted")
	case "projectgroup":
		log.Infof("deleting project group variable")
		_, err := gwclient.DeleteProjectGroupVariable(context.TODO(), variableDeleteOpts.parentRef, variableDeleteOpts.name)
		if err != nil {
			return errors.Errorf("failed to delete project group variable: %w", err)
		}
		log.Infof("project group variable deleted")
	}

	return nil
}
