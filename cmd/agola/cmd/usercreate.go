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

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/services/gateway/api"

	"github.com/spf13/cobra"
)

var cmdUserCreate = &cobra.Command{
	Use:   "create",
	Short: "create a user",
	Run: func(cmd *cobra.Command, args []string) {
		if err := userCreate(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

type userCreateOptions struct {
	username string
}

var userCreateOpts userCreateOptions

func init() {
	flags := cmdUserCreate.Flags()

	flags.StringVarP(&userCreateOpts.username, "username", "n", "", "user name")

	cmdUserCreate.MarkFlagRequired("username")

	cmdUser.AddCommand(cmdUserCreate)
}

func userCreate(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	req := &api.CreateUserRequest{
		UserName: userCreateOpts.username,
	}

	log.Infof("creating user")
	user, _, err := gwclient.CreateUser(context.TODO(), req)
	if err != nil {
		return errors.Wrapf(err, "failed to create user")
	}
	log.Infof("user %q created, ID: %q", user.UserName, user.ID)

	return nil
}
