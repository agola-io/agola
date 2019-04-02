// This file is part of Endless
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

	flags.StringVar(&variableCreateOpts.parentRef, "projectgroup", "", "project group id or full path)")
	flags.StringVarP(&variableCreateOpts.name, "name", "n", "", "variable name")
	flags.StringVar(&variableCreateOpts.values, "values", "", "json list of values and conditions")

	cmdProjectGroupVariableCreate.MarkFlagRequired("project")
	cmdProjectGroupVariableCreate.MarkFlagRequired("name")
	cmdProjectGroupVariableCreate.MarkFlagRequired("values")

	cmdProjectGroupVariable.AddCommand(cmdProjectGroupVariableCreate)
}
