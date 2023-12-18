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

package objectstorage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"agola.io/agola/internal/testutil"
)

func TestPosixDeleteObject(t *testing.T) {
	objects := []string{"☺☺☺☺a☺☺☺☺☺☺b☺☺☺☺", "s3/is/nota/fil.fa", "s3/is/not/a/file///system/fi%l%%e01"}

	dir := t.TempDir()

	ls, err := NewPosix(dir)
	testutil.NilError(t, err)

	for _, obj := range objects {
		err := ls.WriteObject(obj, bytes.NewReader([]byte{}), 0, true)
		testutil.NilError(t, err)

		err = ls.DeleteObject(obj)
		testutil.NilError(t, err)
	}

	// no files and directories should be left
	bd, err := os.Open(filepath.Join(dir, dataDirName))
	testutil.NilError(t, err)

	files, err := bd.Readdirnames(0)
	testutil.NilError(t, err)

	assert.Assert(t, cmp.Len(files, 0), "number of files")
}
