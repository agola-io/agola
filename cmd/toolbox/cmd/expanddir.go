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
	"io"
	"log"
	"os"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

var cmdExpandDir = &cobra.Command{
	Use:   "expanddir",
	Run:   expanddirRun,
	Short: "create the provided directories",
}

func init() {
	CmdToolbox.AddCommand(cmdExpandDir)
}

func expanddirRun(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		log.Fatalf("no directory name specified")
	}

	expDir, err := homedir.Expand(args[0])
	if err != nil {
		log.Fatalf("failed to expand dir %q: %v", expDir, err)
	}

	io.WriteString(os.Stdout, expDir)
}
