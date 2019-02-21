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
	"fmt"

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/services/gateway/api"

	"github.com/spf13/cobra"
)

var cmdUserTokenCreate = &cobra.Command{
	Use:   "create",
	Short: "create a user linkedaccount",
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

	cmdUserTokenCreate.MarkFlagRequired("username")
	cmdUserTokenCreate.MarkFlagRequired("tokenname")

	cmdUserToken.AddCommand(cmdUserTokenCreate)
}

func userTokenCreate(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	req := &api.CreateUserTokenRequest{
		TokenName: userTokenCreateOpts.tokenName,
	}

	log.Infof("creating token for user %q", userTokenCreateOpts.username)
	resp, _, err := gwclient.CreateUserToken(context.TODO(), userTokenCreateOpts.username, req)
	if err != nil {
		return errors.Wrapf(err, "failed to create token")
	}
	log.Infof("token for user %q created: %s", userTokenCreateOpts.username, resp.Token)
	fmt.Println(resp.Token)

	return nil
}
