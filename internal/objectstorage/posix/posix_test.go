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

package posix

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestDeleteObject(t *testing.T) {
	objects := []string{"☺☺☺☺a☺☺☺☺☺☺b☺☺☺☺", "s3/is/nota/fil.fa", "s3/is/not/a/file///system/fi%l%%e01"}

	dir, err := ioutil.TempDir("", "objectstorage")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	//defer os.RemoveAll(dir)

	ls, err := New(dir)
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
