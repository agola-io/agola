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
	"fmt"

	"github.com/sorintlab/agola/internal/services/gateway/api"
	"github.com/spf13/cobra"
)

var cmdProjectList = &cobra.Command{
	Use: "list",
	Run: func(cmd *cobra.Command, args []string) {
		if err := projectList(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
	Short: "list",
}

type projectListOptions struct {
	parentPath string
}

var projectListOpts projectListOptions

func init() {
	flags := cmdProjectList.PersistentFlags()

	flags.StringVar(&projectListOpts.parentPath, "parent", "", `project group path (i.e "org/org01" for root project group in org01, "/user/user01/group01/subgroub01") or project group id`)

	cmdProjectList.MarkFlagRequired("parent")

	cmdProject.AddCommand(cmdProjectList)
}

func printProjects(projects []*api.ProjectResponse) {
	for _, project := range projects {
		fmt.Printf("%s: Name: %s\n", project.ID, project.Name)
	}
}

func projectList(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	projects, _, err := gwclient.GetProjectGroupProjects(context.TODO(), projectListOpts.parentPath)
	if err != nil {
		return err
	}

	printProjects(projects)

	return nil
}
