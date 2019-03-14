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
	flags.StringVar(&projectCreateOpts.parentPath, "parent", "", `parent project group path (i.e "org/org01" for root project group in org01, "/user/user01/group01/subgroub01") or project group id where the project should be created`)

	cmdProjectCreate.MarkFlagRequired("name")
	cmdProjectCreate.MarkFlagRequired("parent")
	cmdProjectCreate.MarkFlagRequired("repo-url")
	cmdProjectCreate.MarkFlagRequired("remote-source")

	cmdProject.AddCommand(cmdProjectCreate)
}

func projectCreate(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	req := &api.CreateProjectRequest{
		Name:                projectCreateOpts.name,
		ParentID:            projectCreateOpts.parentPath,
		RepoURL:             projectCreateOpts.repoURL,
		RemoteSourceName:    projectCreateOpts.remoteSourceName,
		SkipSSHHostKeyCheck: projectCreateOpts.skipSSHHostKeyCheck,
	}

	log.Infof("creating project")

	project, _, err := gwclient.CreateProject(context.TODO(), req)
	if err != nil {
		return errors.Wrapf(err, "failed to create project")
	}
	log.Infof("project %s created, ID: %s", project.Name, project.ID)

	return nil
}
