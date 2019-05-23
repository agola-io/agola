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

	"github.com/sorintlab/agola/internal/services/gateway/api"

	errors "golang.org/x/xerrors"
	"github.com/spf13/cobra"
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

	flags.StringVar(&variableDeleteOpts.parentRef, "project", "", "project id or full path)")
	flags.StringVarP(&variableDeleteOpts.name, "name", "n", "", "variable name")

	cmdProjectVariableDelete.MarkFlagRequired("projectgroup")
	cmdProjectVariableDelete.MarkFlagRequired("name")

	cmdProjectVariable.AddCommand(cmdProjectVariableDelete)
}

func variableDelete(cmd *cobra.Command, ownertype string, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

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
