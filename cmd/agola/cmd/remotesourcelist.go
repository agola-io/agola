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

	"github.com/sorintlab/agola/internal/services/gateway/api"
	"github.com/spf13/cobra"
)

var cmdRemoteSourceList = &cobra.Command{
	Use: "list",
	Run: func(cmd *cobra.Command, args []string) {
		if err := remoteSourceList(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
	Short: "list",
}

type remoteSourceListOptions struct {
	limit int
	start string
}

var remoteSourceListOpts remoteSourceListOptions

func init() {
	flags := cmdRemoteSourceList.PersistentFlags()

	flags.IntVar(&remoteSourceListOpts.limit, "limit", 10, "max number of runs to show")
	flags.StringVar(&remoteSourceListOpts.start, "start", "", "starting user name (excluded) to fetch")

	cmdRemoteSource.AddCommand(cmdRemoteSourceList)
}

func printRemoteSources(remoteSources []*api.RemoteSourceResponse) {
	for _, rs := range remoteSources {
		fmt.Printf("%s: Name: %s\n", rs.ID, rs.Name)
	}
}

func remoteSourceList(cmd *cobra.Command, args []string) error {
	gwclient := api.NewClient(gatewayURL, token)

	remouteSources, _, err := gwclient.GetRemoteSources(context.TODO(), remoteSourceListOpts.start, remoteSourceListOpts.limit, false)
	if err != nil {
		return err
	}

	printRemoteSources(remouteSources)

	return nil
}
