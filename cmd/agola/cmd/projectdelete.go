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

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/services/gateway/api"

	"github.com/spf13/cobra"
)

var cmdProjectDelete = &cobra.Command{
	Use:   "delete",
	Short: "delete a project",
	Run: func(cmd *cobra.Command, args []string) {
		if err := projectDelete(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type projectDeleteOptions struct {
	name             string
	organizationName string
}

var projectDeleteOpts projectDeleteOptions

func init() {
	flags := cmdProjectDelete.Flags()

	flags.StringVarP(&projectDeleteOpts.name, "name", "n", "", "project name")
	flags.StringVar(&projectDeleteOpts.organizationName, "orgname", "", "organization name where the project should be deleted")

	cmdProjectDelete.MarkFlagRequired("name")

	cmdProject.AddCommand(cmdProjectDelete)
}

func projectDelete(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	log.Infof("deleting project")

	var err error
	if projectDeleteOpts.organizationName != "" {
		_, err = gwclient.DeleteOrgProject(context.TODO(), projectDeleteOpts.organizationName, projectDeleteOpts.name)
	} else {
		_, err = gwclient.DeleteCurrentUserProject(context.TODO(), projectDeleteOpts.name)
	}
	if err != nil {
		return errors.Wrapf(err, "failed to delete project")
	}

	return nil
}
