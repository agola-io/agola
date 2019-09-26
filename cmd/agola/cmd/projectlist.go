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
	"fmt"

	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

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
	flags := cmdProjectList.Flags()

	flags.StringVar(&projectListOpts.parentPath, "parent", "", `project group path (i.e "org/org01" for root project group in org01, "user/user01/group01/subgroub01") or project group id`)

	if err := cmdProjectList.MarkFlagRequired("parent"); err != nil {
		log.Fatal(err)
	}

	cmdProject.AddCommand(cmdProjectList)
}

func printProjects(projects []*gwapitypes.ProjectResponse) {
	for _, project := range projects {
		fmt.Printf("%s: Name: %s\n", project.ID, project.Name)
	}
}

func projectList(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	projects, _, err := gwclient.GetProjectGroupProjects(context.TODO(), projectListOpts.parentPath)
	if err != nil {
		return err
	}

	printProjects(projects)

	return nil
}
