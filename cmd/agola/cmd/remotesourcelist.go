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
