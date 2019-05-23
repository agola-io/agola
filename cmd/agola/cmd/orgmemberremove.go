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

	errors "golang.org/x/xerrors"
	"github.com/sorintlab/agola/internal/services/gateway/api"

	"github.com/spf13/cobra"
)

var cmdOrgMemberRemove = &cobra.Command{
	Use:   "remove",
	Short: "removes an organization member",
	Run: func(cmd *cobra.Command, args []string) {
		if err := orgMemberRemove(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type orgMemberRemoveOptions struct {
	orgname  string
	username string
}

var orgMemberRemoveOpts orgMemberRemoveOptions

func init() {
	flags := cmdOrgMemberRemove.Flags()

	flags.StringVarP(&orgMemberRemoveOpts.orgname, "orgname", "n", "", "organization name")
	flags.StringVar(&orgMemberRemoveOpts.username, "username", "", "user name")

	cmdOrgMemberRemove.MarkFlagRequired("orgname")
	cmdOrgMemberRemove.MarkFlagRequired("username")

	cmdOrgMember.AddCommand(cmdOrgMemberRemove)
}

func orgMemberRemove(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	log.Infof("removing member %q from organization %q", orgMemberRemoveOpts.username, orgMemberRemoveOpts.orgname)
	_, err := gwclient.RemoveOrgMember(context.TODO(), orgMemberRemoveOpts.orgname, orgMemberRemoveOpts.username)
	if err != nil {
		return errors.Errorf("failed to remove organization member: %w", err)
	}

	return nil
}
