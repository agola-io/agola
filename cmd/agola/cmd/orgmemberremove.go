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

	gwclient "agola.io/agola/services/gateway/client"

	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
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

	if err := cmdOrgMemberRemove.MarkFlagRequired("orgname"); err != nil {
		log.Fatal(err)
	}
	if err := cmdOrgMemberRemove.MarkFlagRequired("username"); err != nil {
		log.Fatal(err)
	}

	cmdOrgMember.AddCommand(cmdOrgMemberRemove)
}

func orgMemberRemove(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	log.Infof("removing member %q from organization %q", orgMemberRemoveOpts.username, orgMemberRemoveOpts.orgname)
	_, err := gwclient.RemoveOrgMember(context.TODO(), orgMemberRemoveOpts.orgname, orgMemberRemoveOpts.username)
	if err != nil {
		return errors.Errorf("failed to remove organization member: %w", err)
	}

	return nil
}
