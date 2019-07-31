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

var cmdUserTokenDelete = &cobra.Command{
	Use:   "delete",
	Short: "delete a user token",
	Run: func(cmd *cobra.Command, args []string) {
		if err := userTokenDelete(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type userTokenDeleteOptions struct {
	userName  string
	tokenName string
}

var userTokenDeleteOpts userTokenDeleteOptions

func init() {
	flags := cmdUserTokenDelete.Flags()

	flags.StringVarP(&userTokenDeleteOpts.userName, "username", "n", "", "user name")
	flags.StringVarP(&userTokenDeleteOpts.tokenName, "tokenname", "t", "", "token name")

	if err := cmdUserTokenDelete.MarkFlagRequired("username"); err != nil {
		log.Fatal(err)
	}
	if err := cmdUserTokenDelete.MarkFlagRequired("tokenname"); err != nil {
		log.Fatal(err)
	}

	cmdUserToken.AddCommand(cmdUserTokenDelete)
}

func userTokenDelete(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	userName := userTokenDeleteOpts.userName
	tokenName := userTokenDeleteOpts.tokenName

	log.Infof("deleting token %q for user %q", tokenName, userName)
	_, err := gwclient.DeleteUserToken(context.TODO(), userName, tokenName)
	if err != nil {
		return errors.Errorf("failed to delete user token: %w", err)
	}

	log.Infof("token %q for user %q deleted", tokenName, userName)

	return nil
}
