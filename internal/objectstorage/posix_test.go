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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestPosixDeleteObject(t *testing.T) {
	objects := []string{"☺☺☺☺a☺☺☺☺☺☺b☺☺☺☺", "s3/is/nota/fil.fa", "s3/is/not/a/file///system/fi%l%%e01"}

	dir, err := ioutil.TempDir("", "objectstorage")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	//defer os.RemoveAll(dir)

	ls, err := NewPosix(dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	for _, obj := range objects {
		if err := ls.WriteObject(obj, bytes.NewReader([]byte{}), 0, true); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if err := ls.DeleteObject(obj); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}

	// no files and directories should be left
	bd, err := os.Open(filepath.Join(dir, dataDirName))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	files, err := bd.Readdirnames(0)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(files) > 0 {
		t.Fatalf("expected 0 files got %d files", len(files))
	}
}
