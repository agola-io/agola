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

package objectstorage

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestEscapeUnescape(t *testing.T) {
	tests := []struct {
		in       string
		expected string
		err      error
	}{
		{"", "", nil},
		{"/", "%2F", nil},
		{"//", "%2F%2F", nil},
		{"☺", "☺", nil},
		{"☺☺☺☺☺☺☺☺", "☺☺☺☺☺☺☺☺.f", nil},
		{"☺☺☺☺☺☺☺☺", "☺☺☺☺☺☺☺☺.f", nil},
		{"☺☺☺☺☺☺☺☺☺☺☺☺☺☺☺☺", "☺☺☺☺☺☺☺☺/☺☺☺☺☺☺☺☺.f", nil},
		{"☺☺☺☺a☺☺☺☺☺☺☺☺☺☺☺", "☺☺☺☺a☺☺☺/☺☺☺☺☺☺☺☺.f", nil},
		{"☺☺☺☺a☺☺☺☺☺☺b☺☺☺☺", "☺☺☺☺a☺☺☺/☺☺☺b☺☺☺☺.f", nil},
		{"⌘", "⌘", nil},
		{"⌘⌘⌘⌘⌘⌘⌘⌘⌘⌘⌘", "⌘⌘⌘⌘⌘⌘⌘⌘/⌘⌘⌘", nil},

		// These are 16 chars on purpose to test the filemarker behavior
		{"s3/is/not/a/file", "s3%2Fis%2Fno/t%2Fa%2Ffile.f", nil},
		{"s3/is/nota/file/", "s3%2Fis%2Fno/ta%2Ffile%2F.f", nil},
		{"s3/is/nota/files", "s3%2Fis%2Fno/ta%2Ffiles.f", nil},
		{"s3/is/nota/fil.f", "s3%2Fis%2Fno/ta%2Ffil.f.f", nil},

		{"s3/is/nota/fil.fa", "s3%2Fis%2Fno/ta%2Ffil.f/a", nil},
		{"/s3/is/nota/fil.fa/", "%2Fs3%2Fis%2Fn/ota%2Ffil./fa%2F", nil},
		{"s3/is/not/a/file///system/fi%l%%e01", "s3%2Fis%2Fno/t%2Fa%2Ffile/%2F%2F%2Fsyste/m%2Ffi%25l%25%25/e01", nil},
		{"s3/is/not/a/file///system/file01", "s3%2Fis%2Fno/t%2Fa%2Ffile/%2F%2F%2Fsyste/m%2Ffile01.f", nil},
		{"s3/is/not/a/file///system/file01/", "s3%2Fis%2Fno/t%2Fa%2Ffile/%2F%2F%2Fsyste/m%2Ffile01/%2F", nil},
		{"s3/is/not/a/file///system/file01/a", "s3%2Fis%2Fno/t%2Fa%2Ffile/%2F%2F%2Fsyste/m%2Ffile01/%2Fa", nil},
	}

	for i, tt := range tests {
		out := escape(tt.in)
		if out != tt.expected {
			t.Errorf("%d: escape: expected %q got %q", i, tt.expected, out)
		}

		unescaped, _, err := unescape(out)
		if err != nil {
			if tt.err == nil {
				t.Errorf("%d: unescape: expected no error got %v", i, err)
			} else if tt.err != err {
				t.Errorf("%d: unescape: expected error %v got %v", i, tt.err, err)
			}
		} else {
			if tt.err != nil {
				t.Errorf("%d: unescape: expected error %v got no error", i, tt.err)
			} else if unescaped != tt.in {
				t.Errorf("%d: unescape: expected %q got %q", i, tt.in, unescaped)
			}
		}
	}
}

func TestDeleteObject(t *testing.T) {
	objects := []string{"/", "//", "☺☺☺☺a☺☺☺☺☺☺b☺☺☺☺", "s3/is/nota/fil.fa", "s3/is/not/a/file///system/fi%l%%e01"}

	dir, err := ioutil.TempDir("", "objectstorage")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	//defer os.RemoveAll(dir)

	ls, err := NewPosixStorage(dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	for _, obj := range objects {
		if err := ls.WriteObject(obj, bytes.NewReader([]byte{})); err != nil {
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
