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

	"github.com/sorintlab/agola/internal/services/gateway/api"

	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
)

var cmdProjectReconfig = &cobra.Command{
	Use:   "reconfig",
	Short: "reconfigures a project remote (reinstalls ssh deploy key and webhooks",
	Run: func(cmd *cobra.Command, args []string) {
		if err := projectReconfig(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type projectReconfigOptions struct {
	name string
}

var projectReconfigOpts projectReconfigOptions

func init() {
	flags := cmdProjectReconfig.Flags()

	flags.StringVarP(&projectReconfigOpts.name, "name", "n", "", "project name")

	cmdProjectReconfig.MarkFlagRequired("name")

	cmdProject.AddCommand(cmdProjectReconfig)
}

func projectReconfig(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	log.Infof("reconfiguring remote project")
	if _, err := gwclient.ReconfigProject(context.TODO(), projectReconfigOpts.name); err != nil {
		return errors.Errorf("failed to reconfigure remote project: %w", err)
	}
	log.Infof("project reconfigured")

	return nil
}
