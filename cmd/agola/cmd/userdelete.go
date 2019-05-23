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

var cmdUserDelete = &cobra.Command{
	Use:   "delete",
	Short: "delete a user",
	Run: func(cmd *cobra.Command, args []string) {
		if err := userDelete(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type userDeleteOptions struct {
	username string
}

var userDeleteOpts userDeleteOptions

func init() {
	flags := cmdUserDelete.Flags()

	flags.StringVarP(&userDeleteOpts.username, "username", "n", "", "user name")

	cmdUserDelete.MarkFlagRequired("username")

	cmdUser.AddCommand(cmdUserDelete)
}

func userDelete(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	log.Infof("deleting user %q", userDeleteOpts.username)
	if _, err := gwclient.DeleteUser(context.TODO(), userDeleteOpts.username); err != nil {
		return errors.Errorf("failed to delete user: %w", err)
	}

	return nil
}
