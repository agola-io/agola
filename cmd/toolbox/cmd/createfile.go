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
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var cmdCreateFile = &cobra.Command{
	Use:   "createfile",
	Run:   createFileRun,
	Short: "reads data from stdin and writes it to a random file returning its path",
}

type createFileOptions struct {
	user string
}

var createFileOpts createFileOptions

func init() {
	flags := cmdCreateFile.PersistentFlags()

	flags.StringVar(&createFileOpts.user, "user", "", "file owner")

	CmdToolbox.AddCommand(cmdCreateFile)
}

func createFile(r io.Reader) (string, error) {
	// create a temp dir if the image doesn't have one
	tmpDir := os.TempDir()
	if err := os.MkdirAll(tmpDir, 0777); err != nil {
		return "", fmt.Errorf("failed to create tmp dir %q", tmpDir)
	}

	file, err := ioutil.TempFile("", "")
	if err != nil {
		return "", err
	}

	filename := file.Name()
	if _, err := io.Copy(file, r); err != nil {
		file.Close()
		return "", err
	}
	file.Close()

	return filename, nil
}

func createFileRun(cmd *cobra.Command, args []string) {
	filename, err := createFile(os.Stdin)
	if err != nil {
		log.Fatalf("failed to write file: %v", err)
	}

	fmt.Fprint(os.Stdout, filename)
}
