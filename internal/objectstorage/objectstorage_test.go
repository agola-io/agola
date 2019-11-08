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
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func setupPosix(t *testing.T, dir string) (*PosixStorage, error) {
	return NewPosix(path.Join(dir, "posix"))
}

func setupPosixFlat(t *testing.T, dir string) (*PosixFlatStorage, error) {
	return NewPosixFlat(path.Join(dir, "posixflat"))
}

func setupS3(t *testing.T, dir string) (*S3Storage, error) {
	minioEndpoint := os.Getenv("MINIO_ENDPOINT")
	minioAccessKey := os.Getenv("MINIO_ACCESSKEY")
	minioSecretKey := os.Getenv("MINIO_SECRETKEY")
	if minioEndpoint == "" {
		t.Logf("missing MINIO_ENDPOINT env, skipping tests with minio storage")
		return nil, nil
	}

	return NewS3(filepath.Base(dir), "", minioEndpoint, minioAccessKey, minioSecretKey, false)
}

func TestList(t *testing.T) {
	dir, err := ioutil.TempDir("", "objectstorage")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	ps, err := setupPosix(t, dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	pfs, err := setupPosixFlat(t, dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	s3s, err := setupS3(t, dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	type listop struct {
		prefix    string
		start     string
		recursive bool
		expected  []string
	}
	tests := []struct {
		s       map[string]Storage
		objects []string
		ops     []listop
	}{
		{
			map[string]Storage{"posixflat": pfs},
			[]string{
				// Minio (as of 20190201) IMHO is not real S3 since it tries to map to a
				// file system and not a flat namespace like S3. For this reason this test
				// won't work with minio beacuse it creates a file called "path/of" and so
				// it's not possible to create a file "path/of/a" because it needs "of" to
				// be a directory

				// All of the below tests will fail on Minio due to the above reason and also the multiple '/'
				// so we aren't testing these with it

				//"path/of",
				//"path/of/a/file02",
				//"path/of/a/file03",
				//"path/of/a/file04",
				//"path/of/a/file05",

				// These are multiple of 8 chars on purpose to test the filemarker behavior to
				// distinguish between a file or a directory when the files ends at the path
				// separator point
				"s3/is/not/a/file///system/file01",
				"s3/is/not/a/file///system/file02",
				"s3/is/not/a/file///system/file03",
				"s3/is/not/a/file///system/file04",
				"s3/is/not/a/file///system/file041",
				"s3/is/not/a/file///system/file042",
				"s3/is/not/a/file///system/file042/",
				"s3/is/not/a/file///system/file042/a",
				"s3/is/not/a/file///system/file04/a",
				"s3/is/not/a/file///system/file04/b",
				"s3/is/not/a/file///system/file05",
				"s3/is/not/a/file///system/file01a",
				"s3/is/not/a/file///system/file01b",
				"s3/is/not/a/file///system/file01/",
				"s3/is/not/a/file///system/file01/a",
				"s3/is/not/a/file///system/file01/b",
			},
			[]listop{
				{
					prefix:    "/s3/",
					start:     "/s3/is/not/a/file///system/file02",
					recursive: true,
					expected: []string{
						"s3/is/not/a/file///system/file03",
						"s3/is/not/a/file///system/file04",
						"s3/is/not/a/file///system/file04/a",
						"s3/is/not/a/file///system/file04/b",
						"s3/is/not/a/file///system/file041",
						"s3/is/not/a/file///system/file042",
						"s3/is/not/a/file///system/file042/",
						"s3/is/not/a/file///system/file042/a",
						"s3/is/not/a/file///system/file05",
					},
				},
				{
					prefix:    "s3",
					start:     "s3/is/not/a/file///system/file02",
					recursive: true,
					expected: []string{
						"s3/is/not/a/file///system/file03",
						"s3/is/not/a/file///system/file04",
						"s3/is/not/a/file///system/file04/a",
						"s3/is/not/a/file///system/file04/b",
						"s3/is/not/a/file///system/file041",
						"s3/is/not/a/file///system/file042",
						"s3/is/not/a/file///system/file042/",
						"s3/is/not/a/file///system/file042/a",
						"s3/is/not/a/file///system/file05",
					},
				},
				{
					prefix:    "s3/is/not/a/file///system/",
					recursive: false,
					expected: []string{
						"s3/is/not/a/file///system/file01",
						"s3/is/not/a/file///system/file01a",
						"s3/is/not/a/file///system/file01b",
						"s3/is/not/a/file///system/file02",
						"s3/is/not/a/file///system/file03",
						"s3/is/not/a/file///system/file04",
						"s3/is/not/a/file///system/file041",
						"s3/is/not/a/file///system/file042",
						"s3/is/not/a/file///system/file05",
					},
				},
				{
					prefix:    "s3/is/not/a/file///system/",
					recursive: true,
					expected: []string{
						"s3/is/not/a/file///system/file01",
						"s3/is/not/a/file///system/file01/",
						"s3/is/not/a/file///system/file01/a",
						"s3/is/not/a/file///system/file01/b",
						"s3/is/not/a/file///system/file01a",
						"s3/is/not/a/file///system/file01b",
						"s3/is/not/a/file///system/file02",
						"s3/is/not/a/file///system/file03",
						"s3/is/not/a/file///system/file04",
						"s3/is/not/a/file///system/file04/a",
						"s3/is/not/a/file///system/file04/b",
						"s3/is/not/a/file///system/file041",
						"s3/is/not/a/file///system/file042",
						"s3/is/not/a/file///system/file042/",
						"s3/is/not/a/file///system/file042/a",
						"s3/is/not/a/file///system/file05",
					},
				},
			},
		},
		{
			map[string]Storage{"posix": ps, "posixflat": pfs, "minio": s3s},
			[]string{
				// These are multiple of 8 chars on purpose to test the filemarker behavior to
				// distinguish between a file or a directory when the files ends at the path
				// separator point
				"s3/is/not/a/file/sy/st/em/file01",
				"s3/is/not/a/file/sy/st/em/file02",
				"s3/is/not/a/file/sy/st/em/file03",
				"s3/is/not/a/file/sy/st/em/file05",
				"s3/is/not/a/file/sy/st/em/file01a",
				"s3/is/not/a/file/sy/st/em/file01b",
				"s3/is/not/a/file/sy/st/em/file04/a",
				"s3/is/not/a/file/sy/st/em/file04/b",
				"s3/is/not/a/file/sy/st/em/file041",
				"s3/is/not/a/file/sy/st/em/file042/a",
			},
			[]listop{
				{
					prefix:    "/s3/",
					start:     "/s3/is/not/a/file/sy/st/em/file02",
					recursive: true,
					expected: []string{
						"s3/is/not/a/file/sy/st/em/file03",
						"s3/is/not/a/file/sy/st/em/file04/a",
						"s3/is/not/a/file/sy/st/em/file04/b",
						"s3/is/not/a/file/sy/st/em/file041",
						"s3/is/not/a/file/sy/st/em/file042/a",
						"s3/is/not/a/file/sy/st/em/file05",
					},
				},
				{
					prefix:    "s3",
					start:     "s3/is/not/a/file/sy/st/em/file02",
					recursive: true,
					expected: []string{
						"s3/is/not/a/file/sy/st/em/file03",
						"s3/is/not/a/file/sy/st/em/file04/a",
						"s3/is/not/a/file/sy/st/em/file04/b",
						"s3/is/not/a/file/sy/st/em/file041",
						"s3/is/not/a/file/sy/st/em/file042/a",
						"s3/is/not/a/file/sy/st/em/file05",
					},
				},
				{
					prefix:    "s3/is/not/a/file/sy/st/em/",
					recursive: false,
					expected: []string{
						"s3/is/not/a/file/sy/st/em/file01",
						"s3/is/not/a/file/sy/st/em/file01a",
						"s3/is/not/a/file/sy/st/em/file01b",
						"s3/is/not/a/file/sy/st/em/file02",
						"s3/is/not/a/file/sy/st/em/file03",
						"s3/is/not/a/file/sy/st/em/file041",
						"s3/is/not/a/file/sy/st/em/file05",
					},
				},
				{
					prefix:    "s3/is/not/a/file/sy/st/em/",
					recursive: true,
					expected: []string{
						"s3/is/not/a/file/sy/st/em/file01",
						"s3/is/not/a/file/sy/st/em/file01a",
						"s3/is/not/a/file/sy/st/em/file01b",
						"s3/is/not/a/file/sy/st/em/file02",
						"s3/is/not/a/file/sy/st/em/file03",
						"s3/is/not/a/file/sy/st/em/file04/a",
						"s3/is/not/a/file/sy/st/em/file04/b",
						"s3/is/not/a/file/sy/st/em/file041",
						"s3/is/not/a/file/sy/st/em/file042/a",
						"s3/is/not/a/file/sy/st/em/file05",
					},
				},
			},
		},
	}

	for i, tt := range tests {
		for sname, s := range tt.s {
			t.Run(fmt.Sprintf("test with storage type %s", sname), func(t *testing.T) {
				switch s := s.(type) {
				case *S3Storage:
					if s == nil {
						t.SkipNow()
					}
				}
				os := NewObjStorage(s, "/")
				// populate
				for _, p := range tt.objects {
					if err := os.WriteObject(p, strings.NewReader(""), 0, true); err != nil {
						t.Fatalf("%s %d err: %v", sname, i, err)
					}
				}

				doneCh := make(chan struct{})
				defer close(doneCh)
				for j, op := range tt.ops {
					paths := []string{}
					for object := range os.List(op.prefix, op.start, op.recursive, doneCh) {
						if object.Err != nil {
							t.Fatalf("%s %d-%d err: %v", sname, i, j, object.Err)
							return
						}
						paths = append(paths, object.Path)
					}
					if !reflect.DeepEqual(op.expected, paths) {
						t.Errorf("%s %d-%d expected paths %v got %v", sname, i, j, op.expected, paths)
					}
				}
			})
		}
	}
}

func TestWriteObject(t *testing.T) {
	dir, err := ioutil.TempDir("", "objectstorage")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	ps, err := setupPosix(t, dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	pfs, err := setupPosixFlat(t, dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	s3s, err := setupS3(t, dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	newBuf := func(n int64) *bytes.Buffer {
		testBytes := make([]byte, n)
		for i := int64(0); i < n; i++ {
			testBytes[i] = 'a' + byte(i%26)
		}
		return bytes.NewBuffer(testBytes)
	}

	for sname, s := range map[string]Storage{"posix": ps, "posixflat": pfs, "minio": s3s} {
		t.Run(fmt.Sprintf("test with storage type %s", sname), func(t *testing.T) {
			switch s := s.(type) {
			case *S3Storage:
				if s == nil {
					t.SkipNow()
				}
			}
			os := NewObjStorage(s, "/")

			n := int64(10000)

			// Test write without size. Should write whole buffer.
			buf := newBuf(n)
			objName := "obj01"
			if err := os.WriteObject(objName, buf, -1, false); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			oi, err := os.Stat(objName)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if oi.Size != n {
				t.Fatalf("expected object size: %d, got %d", n, oi.Size)
			}

			// Test write with object size equal to buf size.
			buf = newBuf(n)
			objName = "obj02"
			if err := os.WriteObject(objName, buf, n, false); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			oi, err = os.Stat(objName)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if oi.Size != n {
				t.Fatalf("expected object size: %d, got %d", n, oi.Size)
			}

			// Test write with object size less than buf size.
			buf = newBuf(n)
			objName = "obj03"
			size := int64(800)
			if err := os.WriteObject(objName, buf, int64(size), false); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			oi, err = os.Stat(objName)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if oi.Size != size {
				t.Fatalf("expected object size: %d, got %d", size, oi.Size)
			}
			// remaining buf len should be n-size
			if int64(buf.Len()) != n-size {
				t.Fatalf("expected buf lenght: %d, got %d", n-size, buf.Len())
			}
		})
	}
}
