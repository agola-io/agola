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
	"github.com/sorintlab/agola/internal/services/types"

	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
)

var cmdOrgMemberAdd = &cobra.Command{
	Use:   "add",
	Short: "adds or updates an organization member",
	Run: func(cmd *cobra.Command, args []string) {
		if err := orgMemberAdd(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type orgMemberAddOptions struct {
	orgname  string
	username string
	role     string
}

var orgMemberAddOpts orgMemberAddOptions

func init() {
	flags := cmdOrgMemberAdd.Flags()

	flags.StringVarP(&orgMemberAddOpts.orgname, "orgname", "n", "", "organization name")
	flags.StringVar(&orgMemberAddOpts.username, "username", "", "user name")
	flags.StringVarP(&orgMemberAddOpts.role, "role", "r", "member", "member role (owner or member)")

	cmdOrgMemberAdd.MarkFlagRequired("orgname")
	cmdOrgMemberAdd.MarkFlagRequired("username")

	cmdOrgMember.AddCommand(cmdOrgMemberAdd)
}

func orgMemberAdd(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	log.Infof("adding/updating member %q to organization %q with role %q", orgMemberAddOpts.username, orgMemberAddOpts.orgname, orgMemberAddOpts.role)
	_, _, err := gwclient.AddOrgMember(context.TODO(), orgMemberAddOpts.orgname, orgMemberAddOpts.username, types.MemberRole(orgMemberAddOpts.role))
	if err != nil {
		return errors.Errorf("failed to add/update organization member: %w", err)
	}

	return nil
}
