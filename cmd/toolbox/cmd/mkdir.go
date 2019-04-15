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

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

var cmdMkdir = &cobra.Command{
	Use:   "mkdir",
	Run:   mkdirRun,
	Short: "create the provided directories",
}

func init() {
	CmdToolbox.AddCommand(cmdMkdir)
}

func mkdirRun(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		log.Fatalf("no directory name specified")
	}

	for _, dir := range args {
		// expand ~
		expDir, err := homedir.Expand(dir)
		if err != nil {
			log.Fatalf("failed to expand dir %q: %v", dir, err)
		}
		if err := os.MkdirAll(expDir, 0755); err != nil {
			log.Fatalf("failed to create directory %q: %v", expDir, err)
		}
	}
}
