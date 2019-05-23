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

package s3

import (
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/sorintlab/agola/internal/objectstorage/types"

	minio "github.com/minio/minio-go"
	errors "golang.org/x/xerrors"
)

type S3Storage struct {
	bucket      string
	minioClient *minio.Client
	// minio core client user for low level api
	minioCore *minio.Core
}

func New(bucket, location, endpoint, accessKeyID, secretAccessKey string, secure bool) (*S3Storage, error) {
	minioClient, err := minio.New(endpoint, accessKeyID, secretAccessKey, secure)
	if err != nil {
		return nil, err
	}

	minioCore, err := minio.NewCore(endpoint, accessKeyID, secretAccessKey, secure)
	if err != nil {
		return nil, err
	}

	exists, err := minioClient.BucketExists(bucket)
	if err != nil {
		return nil, errors.Errorf("cannot check if bucket %q in location %q exits: %w", bucket, location, err)
	}
	if !exists {
		if err := minioClient.MakeBucket(bucket, location); err != nil {
			return nil, errors.Errorf("cannot create bucket %q in location %q: %w", bucket, location, err)
		}
	}

	return &S3Storage{
		bucket:      bucket,
		minioClient: minioClient,
		minioCore:   minioCore,
	}, nil
}

func (s *S3Storage) Stat(p string) (*types.ObjectInfo, error) {
	oi, err := s.minioClient.StatObject(s.bucket, p, minio.StatObjectOptions{})
	if err != nil {
		merr := minio.ToErrorResponse(err)
		if merr.StatusCode == http.StatusNotFound {
			return nil, types.ErrNotExist
		}
		return nil, merr
	}

	return &types.ObjectInfo{Path: p, LastModified: oi.LastModified}, nil
}

func (s *S3Storage) ReadObject(filepath string) (types.ReadSeekCloser, error) {
	if _, err := s.minioClient.StatObject(s.bucket, filepath, minio.StatObjectOptions{}); err != nil {
		merr := minio.ToErrorResponse(err)
		if merr.StatusCode == http.StatusNotFound {
			return nil, types.ErrNotExist
		}
		return nil, merr
	}
	return s.minioClient.GetObject(s.bucket, filepath, minio.GetObjectOptions{})
}

func (s *S3Storage) WriteObject(filepath string, data io.Reader, size int64, persist bool) error {
	// if size is not specified, limit max object size to defaultMaxObjectSize so
	// minio client will not calculate a very big part size using tons of ram.
	// An alternative is to write the file locally so we can calculate the size and
	// then put it. See commented out code below.
	if size >= 0 {
		_, err := s.minioClient.PutObject(s.bucket, filepath, data, size, minio.PutObjectOptions{ContentType: "application/octet-stream"})
		return err
	}

	// hack to know the real file size or minio will do this in memory with big memory usage since s3 doesn't support real streaming of unknown sizes
	// TODO(sgotti) wait for minio client to expose an api to provide the max object size so we can remove this
	tmpfile, err := ioutil.TempFile(os.TempDir(), "s3")
	if err != nil {
		return err
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	size, err = io.Copy(tmpfile, data)
	if err != nil {
		return err
	}
	if _, err := tmpfile.Seek(0, 0); err != nil {
		return err
	}
	_, err = s.minioClient.PutObject(s.bucket, filepath, tmpfile, size, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	return err
}

func (s *S3Storage) DeleteObject(filepath string) error {
	return s.minioClient.RemoveObject(s.bucket, filepath)
}

func (s *S3Storage) List(prefix, startWith, delimiter string, doneCh <-chan struct{}) <-chan types.ObjectInfo {
	objectCh := make(chan types.ObjectInfo, 1)

	if len(delimiter) > 1 {
		objectCh <- types.ObjectInfo{
			Err: errors.Errorf("wrong delimiter %q", delimiter),
		}
		return objectCh
	}

	// remove leading slash
	if strings.HasPrefix(prefix, "/") {
		prefix = strings.TrimPrefix(prefix, "/")
	}
	if strings.HasPrefix(startWith, "/") {
		startWith = strings.TrimPrefix(startWith, "/")
	}

	// Initiate list objects goroutine here.
	go func(objectCh chan<- types.ObjectInfo) {
		defer close(objectCh)
		// Save continuationToken for next request.
		var continuationToken string
		for {
			// Get list of objects a maximum of 1000 per request.
			result, err := s.minioCore.ListObjectsV2(s.bucket, prefix, continuationToken, false, delimiter, 1000, startWith)
			if err != nil {
				objectCh <- types.ObjectInfo{
					Err: err,
				}
				return
			}

			// If contents are available loop through and send over channel.
			for _, object := range result.Contents {
				select {
				// Send object content.
				case objectCh <- types.ObjectInfo{Path: object.Key, LastModified: object.LastModified}:
				// If receives done from the caller, return here.
				case <-doneCh:
					return
				}
			}

			// If continuation token present, save it for next request.
			if result.NextContinuationToken != "" {
				continuationToken = result.NextContinuationToken
			}

			// Listing ends result is not truncated, return right here.
			if !result.IsTruncated {
				return
			}
		}
	}(objectCh)

	return objectCh
}
