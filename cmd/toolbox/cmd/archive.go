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
	"bufio"
	"encoding/json"
	"log"
	"os"

	"agola.io/agola/internal/toolbox/archive"
	"agola.io/agola/internal/util"
	"github.com/mitchellh/go-homedir"

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
