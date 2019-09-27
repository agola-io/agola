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

var cmdProjectGroupSecretCreate = &cobra.Command{
	Use:   "create",
	Short: "create a project local secret",
	Long: `create a project local secret

The secret data should be provided by a yaml document. Examples:

data01: secretvalue01
data02: secretvalue02
`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := secretCreate(cmd, "projectgroup", args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

func init() {
	flags := cmdProjectGroupSecretCreate.Flags()

	flags.StringVar(&secretCreateOpts.parentRef, "projectgroup", "", "project group id or full path")
	flags.StringVarP(&secretCreateOpts.name, "name", "n", "", "secret name")
	flags.StringVarP(&secretCreateOpts.file, "file", "f", "", `yaml file containing the secret data (use "-" to read from stdin)`)

	if err := cmdProjectGroupSecretCreate.MarkFlagRequired("projectgroup"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectGroupSecretCreate.MarkFlagRequired("name"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectGroupSecretCreate.MarkFlagRequired("file"); err != nil {
		log.Fatal(err)
	}

	cmdProjectGroupSecret.AddCommand(cmdProjectGroupSecretCreate)
}
