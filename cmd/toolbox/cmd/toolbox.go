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
	"github.com/sorintlab/agola/cmd"

	"github.com/spf13/cobra"
)

var CmdToolbox = &cobra.Command{
	Use:     "toolbox",
	Short:   "toolbox",
	Version: cmd.Version,
	// just defined to make --version work
	Run: func(c *cobra.Command, args []string) { c.Help() },
}

func Execute() {
	CmdToolbox.Execute()
}
