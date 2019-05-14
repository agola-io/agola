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
	"encoding/json"
	"os"

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/services/gateway/api"

	"github.com/spf13/cobra"
)

var cmdOrgMemberList = &cobra.Command{
	Use:   "list",
	Short: "lists organization members",
	Run: func(cmd *cobra.Command, args []string) {
		if err := orgMemberList(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type orgMemberListOptions struct {
	orgname  string
	username string
	role     string
}

var orgMemberListOpts orgMemberListOptions

func init() {
	flags := cmdOrgMemberList.Flags()

	flags.StringVarP(&orgMemberListOpts.orgname, "orgname", "n", "", "organization name")

	cmdOrgMemberList.MarkFlagRequired("orgname")

	cmdOrgMember.AddCommand(cmdOrgMemberList)
}

func orgMemberList(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	orgMembers, _, err := gwclient.GetOrgMembers(context.TODO(), orgMemberListOpts.orgname)
	if err != nil {
		return errors.Wrapf(err, "failed to get organization member")
	}

	out, err := json.MarshalIndent(orgMembers, "", "\t")
	if err != nil {
		return err
	}
	os.Stdout.Write(out)

	return nil
}
