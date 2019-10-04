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

	gwclient "agola.io/agola/services/gateway/client"

	"github.com/spf13/cobra"
)

var cmdVersion = &cobra.Command{
	Use:   "version",
	Short: "version",
	Run: func(cmd *cobra.Command, args []string) {
		if err := printVersions(cmd, args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

func init() {
	cmdAgola.AddCommand(cmdVersion)
}

func printVersions(cmd *cobra.Command, args []string) error {
	gwclient := gwclient.NewClient(gatewayURL, token)

	gwversion, _, err := gwclient.GetVersion(context.TODO())
	if err != nil {
		return err
	}

	fmt.Printf("Gateway version:\t%s\n", gwversion.Version)
	fmt.Printf("Client version: \t%s\n", cmdAgola.Version)

	return nil
}
