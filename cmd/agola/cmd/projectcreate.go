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

var cmdProjectCreate = &cobra.Command{
	Use:   "create",
	Short: "create a project",
	Run: func(cmd *cobra.Command, args []string) {
		if err := projectCreate(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type projectCreateOptions struct {
	name                string
	parentPath          string
	repoPath            string
	remoteSourceName    string
	skipSSHHostKeyCheck bool
	visibility          string
	passVarsToForkedPR  bool
}

var projectCreateOpts projectCreateOptions

func init() {
	flags := cmdProjectCreate.Flags()

	flags.StringVarP(&projectCreateOpts.name, "name", "n", "", "project name")
	flags.StringVar(&projectCreateOpts.repoPath, "repo-path", "", "repository path (i.e agola-io/agola)")
	flags.StringVar(&projectCreateOpts.remoteSourceName, "remote-source", "", "remote source name")
	flags.BoolVarP(&projectCreateOpts.skipSSHHostKeyCheck, "skip-ssh-host-key-check", "s", false, "skip ssh host key check")
	flags.StringVar(&projectCreateOpts.parentPath, "parent", "", `parent project group path (i.e "org/org01" for root project group in org01, "user/user01/group01/subgroub01") or project group id where the project should be created`)
	flags.StringVar(&projectCreateOpts.visibility, "visibility", "public", `project visibility (public or private)`)
	flags.BoolVar(&projectCreateOpts.passVarsToForkedPR, "pass-vars-to-forked-pr", false, `pass variables to run even if triggered by PR from forked repo`)

	if err := cmdProjectCreate.MarkFlagRequired("name"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectCreate.MarkFlagRequired("parent"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectCreate.MarkFlagRequired("repo-path"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectCreate.MarkFlagRequired("remote-source"); err != nil {
		log.Fatal(err)
	}

	cmdProject.AddCommand(cmdProjectCreate)
}

func IsValidVisibility(v string) bool {
	switch gwapitypes.Visibility(v) {
	case gwapitypes.VisibilityPublic:
	case gwapitypes.VisibilityPrivate:
	default:
		return false
	}
	return true
}

func projectCreate(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	// TODO(sgotti) make this a custom pflag Value?
	if !IsValidVisibility(projectCreateOpts.visibility) {
		return errors.Errorf("invalid visibility %q", projectCreateOpts.visibility)
	}

	req := &gwapitypes.CreateProjectRequest{
		Name:                projectCreateOpts.name,
		ParentRef:           projectCreateOpts.parentPath,
		Visibility:          gwapitypes.Visibility(projectCreateOpts.visibility),
		RepoPath:            projectCreateOpts.repoPath,
		RemoteSourceName:    projectCreateOpts.remoteSourceName,
		SkipSSHHostKeyCheck: projectCreateOpts.skipSSHHostKeyCheck,
		PassVarsToForkedPR:  projectCreateOpts.passVarsToForkedPR,
	}

	log.Infof("creating project")

	project, _, err := gwclient.CreateProject(context.TODO(), req)
	if err != nil {
		return errors.Errorf("failed to create project: %w", err)
	}
	log.Infof("project %s created, ID: %s", project.Name, project.ID)

	return nil
}
