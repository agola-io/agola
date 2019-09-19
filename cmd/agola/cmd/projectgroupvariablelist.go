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

var cmdProjectGroupVariableList = &cobra.Command{
	Use:   "list",
	Short: "list project group variables",
	Run: func(cmd *cobra.Command, args []string) {
		if err := variableList(cmd, "projectgroup", args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

func init() {
	flags := cmdProjectGroupVariableList.Flags()

	flags.StringVar(&variableListOpts.parentRef, "projectgroup", "", "project group id or full path")

	if err := cmdProjectGroupVariableList.MarkFlagRequired("projectgroup"); err != nil {
		log.Fatal(err)
	}

	cmdProjectGroupVariable.AddCommand(cmdProjectGroupVariableList)
}
