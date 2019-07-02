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
	"github.com/spf13/cobra"
)

var cmdProjectGroupSecretDelete = &cobra.Command{
	Use:   "delete",
	Short: "delete a secret",
	Run: func(cmd *cobra.Command, args []string) {
		if err := secretDelete(cmd, "projectgroup", args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

func init() {
	flags := cmdProjectGroupSecretDelete.Flags()

	flags.StringVar(&secretDeleteOpts.parentRef, "projectgroup", "", "project group id or full path")
	flags.StringVarP(&secretDeleteOpts.name, "name", "n", "", "secret name")

	if err := cmdProjectGroupSecretDelete.MarkFlagRequired("projectgroup"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectGroupSecretDelete.MarkFlagRequired("name"); err != nil {
		log.Fatal(err)
	}

	cmdProjectGroupSecret.AddCommand(cmdProjectGroupSecretDelete)
}
