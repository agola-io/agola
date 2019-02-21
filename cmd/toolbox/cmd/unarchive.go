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
	"bufio"
	"flag"
	"log"
	"os"

	"github.com/sorintlab/agola/internal/toolbox/unarchive"

	"github.com/spf13/cobra"
)

var cmdUnarchive = &cobra.Command{
	Use:   "unarchive",
	Run:   unarchiveRun,
	Short: "Unarchive",
}

type unarchiveOptions struct {
	destDir       string
	overwrite     bool
	removeDestDir bool
}

var unarchiveOpts unarchiveOptions

func init() {
	flags := cmdUnarchive.PersistentFlags()

	flags.StringVar(&unarchiveOpts.destDir, "destdir", "", "destination directory")
	flags.BoolVar(&unarchiveOpts.overwrite, "overwrite", false, "overwrite destination files")
	flags.BoolVar(&unarchiveOpts.removeDestDir, "remove-destdir", false, "remove destination directory")

	CmdToolbox.AddCommand(cmdUnarchive)
}

func unarchiveRun(cmd *cobra.Command, args []string) {
	flag.Parse()

	br := bufio.NewReader(os.Stdin)

	if err := unarchive.Unarchive(br, unarchiveOpts.destDir, unarchiveOpts.overwrite, unarchiveOpts.removeDestDir); err != nil {
		log.Fatalf("untar error: %v", err)
	}
}
