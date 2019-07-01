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

	"agola.io/agola/internal/services/gateway/api"
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

func printUsers(users []*api.UserResponse) {
	for _, user := range users {
		fmt.Printf("%s: Name: %s\n", user.ID, user.UserName)
	}
}

func userList(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	users, _, err := gwclient.GetUsers(context.TODO(), userListOpts.start, userListOpts.limit, false)
	if err != nil {
		return err
	}

	printUsers(users)

	return nil
}
