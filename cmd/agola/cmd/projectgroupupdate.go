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

	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
)

var cmdProjectGroupUpdate = &cobra.Command{
	Use:   "update",
	Short: "update a project group",
	Run: func(cmd *cobra.Command, args []string) {
		if err := projectGroupUpdate(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type projectGroupUpdateOptions struct {
	ref string

	name       string
	parentPath string
	visibility string
}

var projectGroupUpdateOpts projectGroupUpdateOptions

func init() {
	flags := cmdProjectGroupUpdate.Flags()

	flags.StringVarP(&projectGroupUpdateOpts.ref, "ref", "", "", "current project group path or id")
	flags.StringVarP(&projectGroupUpdateOpts.name, "name", "n", "", "project group name")
	flags.StringVar(&projectGroupUpdateOpts.parentPath, "parent", "", `parent project group path (i.e "org/org01" for root project group in org01, "user/user01/group01/subgroub01") or project group id where the project group should be moved`)
	flags.StringVar(&projectGroupUpdateOpts.visibility, "visibility", "public", `project group visibility (public or private)`)

	if err := cmdProjectGroupUpdate.MarkFlagRequired("ref"); err != nil {
		log.Fatal(err)
	}

	cmdProjectGroup.AddCommand(cmdProjectGroupUpdate)
}

func projectGroupUpdate(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	req := &gwapitypes.UpdateProjectGroupRequest{}

	flags := cmd.Flags()
	if flags.Changed("name") {
		req.Name = &projectGroupUpdateOpts.name
	}
	if flags.Changed("parent") {
		req.ParentRef = &projectGroupUpdateOpts.parentPath
	}
	if flags.Changed("visibility") {
		if !IsValidVisibility(projectGroupUpdateOpts.visibility) {
			return errors.Errorf("invalid visibility %q", projectGroupUpdateOpts.visibility)
		}
		req.Name = &projectGroupUpdateOpts.visibility
	}

	log.Infof("updating project group")
	projectGroup, _, err := gwclient.UpdateProjectGroup(context.TODO(), projectGroupUpdateOpts.ref, req)
	if err != nil {
		return errors.Errorf("failed to update project group: %w", err)
	}
	log.Infof("project group %s update, ID: %s", projectGroup.Name, projectGroup.ID)

	return nil
}
