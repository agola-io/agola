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

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/services/gateway/api"
	"github.com/sorintlab/agola/internal/services/types"

	"github.com/spf13/cobra"
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
	organizationName    string
	repoURL             string
	remoteSourceName    string
	skipSSHHostKeyCheck bool
}

var projectCreateOpts projectCreateOptions

func init() {
	flags := cmdProjectCreate.Flags()

	flags.StringVarP(&projectCreateOpts.name, "name", "n", "", "project name")
	flags.StringVar(&projectCreateOpts.repoURL, "repo-url", "", "repository url")
	flags.StringVar(&projectCreateOpts.remoteSourceName, "remote-source", "", "remote source name")
	flags.BoolVarP(&projectCreateOpts.skipSSHHostKeyCheck, "skip-ssh-host-key-check", "s", false, "skip ssh host key check")
	flags.StringVar(&projectCreateOpts.organizationName, "orgname", "", "organization name where the project should be created")

	cmdProjectCreate.MarkFlagRequired("name")
	cmdProjectCreate.MarkFlagRequired("repo-url")
	cmdProjectCreate.MarkFlagRequired("remote-source")

	cmdProject.AddCommand(cmdProjectCreate)
}

func projectCreate(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	req := &api.CreateProjectRequest{
		Name:                projectCreateOpts.name,
		RepoURL:             projectCreateOpts.repoURL,
		RemoteSourceName:    projectCreateOpts.remoteSourceName,
		SkipSSHHostKeyCheck: projectCreateOpts.skipSSHHostKeyCheck,
	}

	log.Infof("creating project")

	var project *types.Project
	var err error
	if projectCreateOpts.organizationName != "" {
		project, _, err = gwclient.CreateOrgProject(context.TODO(), projectCreateOpts.organizationName, req)
	} else {
		project, _, err = gwclient.CreateCurrentUserProject(context.TODO(), req)
	}
	if err != nil {
		return errors.Wrapf(err, "failed to create project")
	}
	log.Infof("project %s created, ID: %s", project.Name, project.ID)

	return nil
}
