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
	"log"
	"os"
	"syscall"

	"github.com/spf13/cobra"
)

var cmdShell = &cobra.Command{
	Use:   "shell",
	Run:   shellRun,
	Short: "reads data from stdin, saves it to a file and the executes it with the provided shell",
}

func init() {
	CmdToolbox.AddCommand(cmdShell)
}

func shellRun(cmd *cobra.Command, args []string) {
	filename, err := createFile(os.Stdin)
	if err != nil {
		log.Fatalf("failed to write file: %v", err)
	}

	env := os.Environ()

	args = append(args, filename)
	if err := syscall.Exec(args[0], args, env); err != nil {
		log.Fatalf("failed to exec: %v", err)
	}
}
