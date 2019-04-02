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

var cmdProjectGroupSecretCreate = &cobra.Command{
	Use:   "create",
	Short: "create a project group secret",
	Run: func(cmd *cobra.Command, args []string) {
		if err := secretCreate(cmd, "projectgroup", args); err != nil {
			log.Fatalf("err: %v", err)
		}
	},
}

func init() {
	flags := cmdProjectGroupSecretCreate.Flags()

	flags.StringVar(&secretCreateOpts.projectRef, "project", "", "project id or full path")
	flags.StringVarP(&secretCreateOpts.name, "name", "n", "", "secret name")

	cmdProjectGroupSecretCreate.MarkFlagRequired("project")
	cmdProjectGroupSecretCreate.MarkFlagRequired("name")

	cmdProjectGroupSecret.AddCommand(cmdProjectGroupSecretCreate)
}
