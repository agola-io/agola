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

	"github.com/sorintlab/agola/internal/services/gateway/api"
	"github.com/spf13/cobra"
)

var cmdUserList = &cobra.Command{
	Use: "list",
	Run: func(cmd *cobra.Command, args []string) {
		if err := userList(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
	Short: "list",
}

type userListOptions struct {
	limit int
	start string
}

var userListOpts userListOptions

func init() {
	flags := cmdUserList.PersistentFlags()

	flags.IntVar(&userListOpts.limit, "limit", 10, "max number of runs to show")
	flags.StringVar(&userListOpts.start, "start", "", "starting user name (excluded) to fetch")

	cmdUser.AddCommand(cmdUserList)
}

func printUsers(usersResponse *api.UsersResponse) {
	for _, user := range usersResponse.Users {
		fmt.Printf("%s: Name: %s\n", user.ID, user.UserName)
	}
}

func userList(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	usersResponse, _, err := gwclient.GetUsers(context.TODO(), userListOpts.start, userListOpts.limit, false)
	if err != nil {
		return err
	}

	printUsers(usersResponse)

	return nil
}
