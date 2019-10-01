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
	visibility string
}

var projectGroupCreateOpts projectGroupCreateOptions

func init() {
	flags := cmdProjectGroupCreate.Flags()

	flags.StringVarP(&projectGroupCreateOpts.name, "name", "n", "", "project group name")
	flags.StringVar(&projectGroupCreateOpts.parentPath, "parent", "", `parent project group path (i.e "org/org01" for root project group in org01, "user/user01/group01/subgroub01") or project group id where the project group should be created`)
	flags.StringVar(&projectGroupCreateOpts.visibility, "visibility", "public", `project group visibility (public or private)`)

	if err := cmdProjectGroupCreate.MarkFlagRequired("name"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectGroupCreate.MarkFlagRequired("parent"); err != nil {
		log.Fatal(err)
	}

	cmdProjectGroup.AddCommand(cmdProjectGroupCreate)
}

func projectGroupCreate(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	// TODO(sgotti) make this a custom pflag Value?
	if !IsValidVisibility(projectGroupCreateOpts.visibility) {
		return errors.Errorf("invalid visibility %q", projectGroupCreateOpts.visibility)
	}

	req := &gwapitypes.CreateProjectGroupRequest{
		Name:       projectGroupCreateOpts.name,
		ParentRef:  projectGroupCreateOpts.parentPath,
		Visibility: gwapitypes.Visibility(projectGroupCreateOpts.visibility),
	}

	log.Infof("creating project group")

	projectGroup, _, err := gwclient.CreateProjectGroup(context.TODO(), req)
	if err != nil {
		return errors.Errorf("failed to create project group: %w", err)
	}
	log.Infof("project group %s created, ID: %s", projectGroup.Name, projectGroup.ID)

	return nil
}
