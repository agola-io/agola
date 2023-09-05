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

func orgMemberList(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)
	var orgMembersAll []*gwapitypes.OrgMemberResponse

	hasMoreData := true
	var cursor string
	for hasMoreData {
		orgMembers, _, err := gwclient.GetOrgMembers(context.TODO(), orgMemberListOpts.orgname, false, 0, "")
		if err != nil {
			return errors.Wrapf(err, "failed to get organization member")
		}
		orgMembersAll = append(orgMembersAll, orgMembers.OrgMembers...)
		cursor = orgMembers.Cursor
		hasMoreData = cursor != ""
	}

	out, err := json.MarshalIndent(orgMembersAll, "", "\t")
	if err != nil {
		return errors.WithStack(err)
	}
	os.Stdout.Write(out)

	return nil
}
