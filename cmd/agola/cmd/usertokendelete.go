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

	cmdUserTokenDelete.MarkFlagRequired("username")
	cmdUserTokenDelete.MarkFlagRequired("tokenname")

	cmdUserToken.AddCommand(cmdUserTokenDelete)
}

func userTokenDelete(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

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
