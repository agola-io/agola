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
	"context"
	"io"
	"net/http"
	"os"
	"strings"

	minio "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/util"
)

type S3Storage struct {
	bucket      string
	minioClient *minio.Client
	// minio core client user for low level api
	minioCore *minio.Core
}

func NewS3(ctx context.Context, bucket, location, endpoint, accessKeyID, secretAccessKey string, secure bool) (*S3Storage, error) {
	minioClient, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(accessKeyID, secretAccessKey, ""), Secure: secure})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	minioCore, err := minio.NewCore(endpoint, &minio.Options{Creds: credentials.NewStaticV4(accessKeyID, secretAccessKey, ""), Secure: secure})
	if err != nil {
		return nil, errors.WithStack(err)
	}

	exists, err := minioClient.BucketExists(ctx, bucket)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot check if bucket %q in location %q exits", bucket, location)
	}
	if !exists {
		if err := minioClient.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: location}); err != nil {
			return nil, errors.Wrapf(err, "cannot create bucket %q in location %q", bucket, location)
		}
	}

	return &S3Storage{
		bucket:      bucket,
		minioClient: minioClient,
		minioCore:   minioCore,
	}, nil
}

func (s *S3Storage) Stat(ctx context.Context, p string) (*ObjectInfo, error) {
	oi, err := s.minioClient.StatObject(ctx, s.bucket, p, minio.StatObjectOptions{})
	if err != nil {
		merr := minio.ToErrorResponse(err)
		if merr.StatusCode == http.StatusNotFound {
			return nil, NewErrNotExist(err, "object %q doesn't exist", p)
		}
		return nil, errors.WithStack(merr)
	}

	return &ObjectInfo{Path: p, LastModified: oi.LastModified, Size: oi.Size}, nil
}

func (s *S3Storage) ReadObject(ctx context.Context, filepath string) (ReadSeekCloser, error) {
	if _, err := s.minioClient.StatObject(ctx, s.bucket, filepath, minio.StatObjectOptions{}); err != nil {
		merr := minio.ToErrorResponse(err)
		if merr.StatusCode == http.StatusNotFound {
			return nil, NewErrNotExist(err, "object %q doesn't exist", filepath)
		}
		return nil, errors.WithStack(merr)
	}

	o, err := s.minioClient.GetObject(ctx, s.bucket, filepath, minio.GetObjectOptions{})

	return o, errors.WithStack(err)
}

func (s *S3Storage) WriteObject(ctx context.Context, filepath string, data io.Reader, size int64, persist bool) error {
	// if size is not specified, limit max object size to defaultMaxObjectSize so
	// minio client will not calculate a very big part size using tons of ram.
	// An alternative is to write the file locally so we can calculate the size and
	// then put it. See commented out code below.
	if size >= 0 {
		lr := io.LimitReader(data, size)
		_, err := s.minioClient.PutObject(ctx, s.bucket, filepath, lr, size, minio.PutObjectOptions{ContentType: "application/octet-stream"})
		return errors.WithStack(err)
	}

	// hack to know the real file size or minio will do this in memory with big memory usage since s3 doesn't support real streaming of unknown sizes
	// TODO(sgotti) wait for minio client to expose an api to provide the max object size so we can remove this
	tmpfile, err := os.CreateTemp(os.TempDir(), "s3")
	if err != nil {
		return errors.WithStack(err)
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	size, err = io.Copy(tmpfile, data)
	if err != nil {
		return errors.WithStack(err)
	}
	if _, err := tmpfile.Seek(0, 0); err != nil {
		return errors.WithStack(err)
	}
	_, err = s.minioClient.PutObject(ctx, s.bucket, filepath, tmpfile, size, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	return errors.WithStack(err)
}

func (s *S3Storage) DeleteObject(ctx context.Context, filepath string) error {
	return errors.WithStack(s.minioClient.RemoveObject(ctx, s.bucket, filepath, minio.RemoveObjectOptions{}))
}

func (s *S3Storage) List(ctx context.Context, prefix, startAfter string, recursive bool) <-chan ObjectInfo {
	objectCh := make(chan ObjectInfo, 1)

	// remove leading slash
	prefix = strings.TrimPrefix(prefix, "/")
	startAfter = strings.TrimPrefix(startAfter, "/")

	go func(objectCh chan<- ObjectInfo) {
		defer func() {
			if util.ContextCanceled(ctx) {
				objectCh <- ObjectInfo{
					Err: ctx.Err(),
				}
			}
			close(objectCh)
		}()

		for object := range s.minioClient.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: recursive, StartAfter: startAfter}) {
			if object.Err != nil {
				select {
				case objectCh <- ObjectInfo{Err: object.Err}:
				case <-ctx.Done():
				}
				return
			}

			// minioClient.ListObject also returns common prefixes as objects, but we only want objects
			if strings.HasSuffix(object.Key, "/") {
				continue
			}

			select {
			case objectCh <- ObjectInfo{Path: object.Key, LastModified: object.LastModified, Size: object.Size}:
			case <-ctx.Done():
				return
			}
		}
	}(objectCh)

	return objectCh
}
