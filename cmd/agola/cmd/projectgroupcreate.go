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

var cmdProjectGroupCreate = &cobra.Command{
	Use:   "create",
	Short: "create a project group",
	Run: func(cmd *cobra.Command, args []string) {
		if err := projectGroupCreate(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type projectGroupCreateOptions struct {
	name       string
	parentPath string
}

var projectGroupCreateOpts projectGroupCreateOptions

func init() {
	flags := cmdProjectGroupCreate.Flags()

	flags.StringVarP(&projectGroupCreateOpts.name, "name", "n", "", "project group name")
	flags.StringVar(&projectGroupCreateOpts.parentPath, "parent", "", `parent project group path (i.e "org/org01" for root project group in org01, "user/user01/group01/subgroub01") or project group id where the project group should be created`)

	cmdProjectGroupCreate.MarkFlagRequired("name")
	cmdProjectGroupCreate.MarkFlagRequired("parent")

	cmdProjectGroup.AddCommand(cmdProjectGroupCreate)
}

func projectGroupCreate(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	req := &api.CreateProjectGroupRequest{
		Name:     projectGroupCreateOpts.name,
		ParentID: projectGroupCreateOpts.parentPath,
	}

	log.Infof("creating project group")

	project, _, err := gwclient.CreateProjectGroup(context.TODO(), req)
	if err != nil {
		return errors.Wrapf(err, "failed to create project group")
	}
	log.Infof("project group %s created, ID: %s", project.Name, project.ID)

	return nil
}
