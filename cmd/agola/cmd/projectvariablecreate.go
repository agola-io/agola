// This file is part of Endless
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

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/services/gateway/api"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/spf13/cobra"
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

	flags.StringVar(&variableCreateOpts.parentRef, "project", "", "project id or full path)")
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
			return errors.Wrapf(err, "failed to create project variable")
		}
		log.Infof("project variable %q created, ID: %q", variable.Name, variable.ID)
	case "projectgroup":
		log.Infof("creating project group variable")
		variable, _, err := gwclient.CreateProjectGroupVariable(context.TODO(), variableCreateOpts.parentRef, req)
		if err != nil {
			return errors.Wrapf(err, "failed to create project group variable")
		}
		log.Infof("project group variable %q created, ID: %q", variable.Name, variable.ID)
	}

	return nil
}
