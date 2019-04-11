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
