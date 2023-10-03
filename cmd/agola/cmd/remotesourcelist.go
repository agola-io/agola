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

	"github.com/rs/zerolog/log"
	"github.com/sorintlab/errors"
	"github.com/spf13/cobra"

	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"
)

var cmdRemoteSourceList = &cobra.Command{
	Use: "list",
	Run: func(cmd *cobra.Command, args []string) {
		if err := remoteSourceList(cmd, args); err != nil {
			log.Fatal().Err(err).Send()
		}
	},
	Short: "list",
}

func init() {
	cmdRemoteSource.AddCommand(cmdRemoteSourceList)
}

func printRemoteSources(remoteSources []*gwapitypes.RemoteSourceResponse) {
	for _, rs := range remoteSources {
		fmt.Printf("%s: Name: %s\n", rs.ID, rs.Name)
	}
}

func remoteSourceList(cmd *cobra.Command, args []string) error {
	gwClient := gwclient.NewClient(gatewayURL, token)

	var cursor string
	for {
		remoteSources, resp, err := gwClient.GetRemoteSources(context.TODO(), &gwclient.ListOptions{Cursor: cursor})
		if err != nil {
			return errors.Wrapf(err, "failed to get remote sources")
		}
		printRemoteSources(remoteSources)

		cursor = resp.Cursor
		if cursor == "" {
			break
		}
	}

	return nil
}
