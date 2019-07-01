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
	"encoding/json"

	"agola.io/agola/internal/services/gateway/api"
	"agola.io/agola/internal/services/types"

	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
)

var cmdProjectVariableCreate = &cobra.Command{
	Use:   "create",
	Short: "create a project variable",
	Run: func(cmd *cobra.Command, args []string) {
		if err := variableCreate(cmd, "project", args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type variableCreateOptions struct {
	parentRef string
	name      string
	values    string
}

var variableCreateOpts variableCreateOptions

func init() {
	flags := cmdProjectVariableCreate.Flags()

	flags.StringVar(&variableCreateOpts.parentRef, "project", "", "project id or full path")
	flags.StringVarP(&variableCreateOpts.name, "name", "n", "", "variable name")
	flags.StringVar(&variableCreateOpts.values, "values", "", "json list of values and conditions")

	cmdProjectVariableCreate.MarkFlagRequired("project")
	cmdProjectVariableCreate.MarkFlagRequired("name")
	cmdProjectVariableCreate.MarkFlagRequired("values")

	cmdProjectVariable.AddCommand(cmdProjectVariableCreate)
}

func variableCreate(cmd *cobra.Command, ownertype string, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	var values []types.VariableValue
	if err := json.Unmarshal([]byte(variableCreateOpts.values), &values); err != nil {
		log.Fatalf("failed to unmarshall values: %v", err)
	}
	req := &api.CreateVariableRequest{
		Name:   variableCreateOpts.name,
		Values: values,
	}

	switch ownertype {
	case "project":
		log.Infof("creating project variable")
		variable, _, err := gwclient.CreateProjectVariable(context.TODO(), variableCreateOpts.parentRef, req)
		if err != nil {
			return errors.Errorf("failed to create project variable: %w", err)
		}
		log.Infof("project variable %q created, ID: %q", variable.Name, variable.ID)
	case "projectgroup":
		log.Infof("creating project group variable")
		variable, _, err := gwclient.CreateProjectGroupVariable(context.TODO(), variableCreateOpts.parentRef, req)
		if err != nil {
			return errors.Errorf("failed to create project group variable: %w", err)
		}
		log.Infof("project group variable %q created, ID: %q", variable.Name, variable.ID)
	}

	return nil
}
