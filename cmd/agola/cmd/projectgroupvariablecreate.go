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
	Short: "create a project variable",
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
	flags.StringVar(&variableCreateOpts.values, "values", "", "json list of values and conditions")

	cmdProjectGroupVariableCreate.MarkFlagRequired("project")
	cmdProjectGroupVariableCreate.MarkFlagRequired("name")
	cmdProjectGroupVariableCreate.MarkFlagRequired("values")

	cmdProjectGroupVariable.AddCommand(cmdProjectGroupVariableCreate)
}
