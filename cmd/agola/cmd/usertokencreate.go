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
	"fmt"

	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"

	"github.com/spf13/cobra"
	errors "golang.org/x/xerrors"
)

var cmdUserTokenCreate = &cobra.Command{
	Use:   "create",
	Short: "create a user token",
	Run: func(cmd *cobra.Command, args []string) {
		if err := userTokenCreate(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type userTokenCreateOptions struct {
	username  string
	tokenName string
}

var userTokenCreateOpts userTokenCreateOptions

func init() {
	flags := cmdUserTokenCreate.Flags()

	flags.StringVarP(&userTokenCreateOpts.username, "username", "n", "", "user name")
	flags.StringVarP(&userTokenCreateOpts.tokenName, "tokenname", "t", "", "token name")

	if err := cmdUserTokenCreate.MarkFlagRequired("username"); err != nil {
		log.Fatal(err)
	}
	if err := cmdUserTokenCreate.MarkFlagRequired("tokenname"); err != nil {
		log.Fatal(err)
	}

	cmdUserToken.AddCommand(cmdUserTokenCreate)
}

func userTokenCreate(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	req := &gwapitypes.CreateUserTokenRequest{
		TokenName: userTokenCreateOpts.tokenName,
	}

	log.Infof("creating token for user %q", userTokenCreateOpts.username)
	resp, _, err := gwclient.CreateUserToken(context.TODO(), userTokenCreateOpts.username, req)
	if err != nil {
		return errors.Errorf("failed to create token: %w", err)
	}
	log.Infof("token for user %q created: %s", userTokenCreateOpts.username, resp.Token)
	fmt.Println(resp.Token)

	return nil
}
