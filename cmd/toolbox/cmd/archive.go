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
	"encoding/json"
	"log"
	"os"

	"github.com/mitchellh/go-homedir"
	"github.com/sorintlab/agola/internal/toolbox/archive"
	"github.com/sorintlab/agola/internal/util"

	"github.com/spf13/cobra"
)

var cmdArchive = &cobra.Command{
	Use:   "archive",
	Run:   archiveRun,
	Short: "Archive",
}

func init() {
	CmdToolbox.AddCommand(cmdArchive)
}

func archiveRun(cmd *cobra.Command, args []string) {
	br := bufio.NewReader(os.Stdin)
	d := json.NewDecoder(br)

	a := archive.Archive{}
	if err := d.Decode(&a); err != nil {
		log.Fatalf("err: %v", err)
	}

	log.Printf("archive: %s", util.Dump(a))

	var out *os.File
	if a.OutFile == "" {
		out = os.Stdout
	} else {
		var err error
		out, err = os.Create(a.OutFile)
		if err != nil {
			log.Fatalf("error creating %s: %v", a.OutFile, err)
		}
		defer out.Close()
	}

	// expand ~ in archiveinfos SourceDir
	for i := range a.ArchiveInfos {
		exp, err := homedir.Expand(a.ArchiveInfos[i].SourceDir)
		if err != nil {
			log.Fatalf("failed to expand dir %q: %v", a.ArchiveInfos[i].SourceDir, err)
		}

		a.ArchiveInfos[i].SourceDir = exp
	}

	if err := archive.CreateTar(a.ArchiveInfos, out); err != nil {
		log.Fatalf("create tar error: %v", err)
	}
}
