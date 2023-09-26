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
	"encoding/json"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/sorintlab/errors"
	"github.com/spf13/cobra"

	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"
)

var cmdOrgMemberList = &cobra.Command{
	Use:   "list",
	Short: "lists organization members",
	Run: func(cmd *cobra.Command, args []string) {
		if err := orgMemberList(cmd, args); err != nil {
			log.Fatal().Err(err).Send()
		}
	},
}

type orgMemberListOptions struct {
	orgname string
}

var orgMemberListOpts orgMemberListOptions

func init() {
	flags := cmdOrgMemberList.Flags()

	flags.StringVarP(&orgMemberListOpts.orgname, "orgname", "n", "", "organization name")

	if err := cmdOrgMemberList.MarkFlagRequired("orgname"); err != nil {
		log.Fatal().Err(err).Send()
	}

	cmdOrgMember.AddCommand(cmdOrgMemberList)
}

func printOrgMembers(orgMembers []*gwapitypes.OrgMemberResponse) error {
	for _, orgMember := range orgMembers {
		out, err := json.MarshalIndent(orgMember, "", "\t")
		if err != nil {
			return errors.WithStack(err)
		}
		os.Stdout.Write(out)
	}

	return nil
}

func orgMemberList(cmd *cobra.Command, args []string) error {
	gwClient := gwclient.NewClient(gatewayURL, token)

	var cursor string
	for {
		orgMembersResp, resp, err := gwClient.GetOrgMembers(context.TODO(), orgMemberListOpts.orgname, &gwclient.ListOptions{Cursor: cursor})
		if err != nil {
			return errors.Wrapf(err, "failed to get organization member")
		}

		if err := printOrgMembers(orgMembersResp.Members); err != nil {
			return errors.WithStack(err)
		}

		cursor = resp.Cursor
		if cursor == "" {
			break
		}
	}

	return nil
}
