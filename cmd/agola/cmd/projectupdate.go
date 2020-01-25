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

var cmdProjectUpdate = &cobra.Command{
	Use:   "update",
	Short: "update a project",
	Run: func(cmd *cobra.Command, args []string) {
		if err := projectUpdate(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type projectUpdateOptions struct {
	ref string

	name               string
	parentPath         string
	visibility         string
	passVarsToForkedPR bool
}

var projectUpdateOpts projectUpdateOptions

func init() {
	flags := cmdProjectUpdate.Flags()

	flags.StringVarP(&projectUpdateOpts.ref, "ref", "", "", "current project path or id")
	flags.StringVarP(&projectUpdateOpts.name, "name", "n", "", "project name")
	flags.StringVar(&projectUpdateOpts.parentPath, "parent", "", `parent project group path (i.e "org/org01" for root project group in org01, "user/user01/group01/subgroub01") or project group id where the project should be moved`)
	flags.StringVar(&projectUpdateOpts.visibility, "visibility", "public", `project visibility (public or private)`)
	flags.BoolVar(&projectUpdateOpts.passVarsToForkedPR, "pass-vars-to-forked-pr", false, `pass variables to run even if triggered by PR from forked repo`)

	if err := cmdProjectUpdate.MarkFlagRequired("ref"); err != nil {
		log.Fatal(err)
	}

	cmdProject.AddCommand(cmdProjectUpdate)
}

func projectUpdate(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	req := &gwapitypes.UpdateProjectRequest{}

	flags := cmd.Flags()
	if flags.Changed("name") {
		req.Name = &projectUpdateOpts.name
	}
	if flags.Changed("parent") {
		req.ParentRef = &projectUpdateOpts.parentPath
	}
	if flags.Changed("visibility") {
		if !IsValidVisibility(projectUpdateOpts.visibility) {
			return errors.Errorf("invalid visibility %q", projectUpdateOpts.visibility)
		}
		visibility := gwapitypes.Visibility(projectUpdateOpts.visibility)
		req.Visibility = &visibility
	}
	if flags.Changed("pass-vars-to-forked-pr") {
		req.PassVarsToForkedPR = &projectUpdateOpts.passVarsToForkedPR
	}

	log.Infof("updating project")
	project, _, err := gwclient.UpdateProject(context.TODO(), projectUpdateOpts.ref, req)
	if err != nil {
		return errors.Errorf("failed to update project: %w", err)
	}
	log.Infof("project %s update, ID: %s", project.Name, project.ID)

	return nil
}
