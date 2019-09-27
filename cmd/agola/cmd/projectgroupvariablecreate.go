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

var cmdProjectGroupVariableCreate = &cobra.Command{
	Use:   "create",
	Short: "create a project group variable",
	Long: `create a project group variable

The variable values should be provided by a yaml document. Examples:

- secret_name: secret01
  secret_var: var01
  when:
    branch: master
    tag:
      - v1.x
      - v2.x
- secret_name: secret02
  secret_var: data02
  when:
    ref:
      include:
        - '#/refs/pull/.*#'
        - '#/refs/heads/devel.*#'
      exclude: /refs/heads/develop

The above yaml document defines a variable that can have two different values depending on the first matching condition.
	`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := variableCreate(cmd, "projectgroup", args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

func init() {
	flags := cmdProjectGroupVariableCreate.Flags()

	flags.StringVar(&variableCreateOpts.parentRef, "projectgroup", "", "project group id or full path")
	flags.StringVarP(&variableCreateOpts.name, "name", "n", "", "variable name")
	flags.StringVarP(&variableCreateOpts.file, "file", "f", "", `yaml file containing the variable definition (use "-" to read from stdin)`)

	if err := cmdProjectGroupVariableCreate.MarkFlagRequired("projectgroup"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectGroupVariableCreate.MarkFlagRequired("name"); err != nil {
		log.Fatal(err)
	}
	if err := cmdProjectGroupVariableCreate.MarkFlagRequired("file"); err != nil {
		log.Fatal(err)
	}

	cmdProjectGroupVariable.AddCommand(cmdProjectGroupVariableCreate)
}
