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
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	minio "github.com/minio/minio-go"
	"github.com/pkg/errors"
)

type S3Storage struct {
	bucket      string
	minioClient *minio.Client
	// minio core client user for low level api
	minioCore *minio.Core
}

func NewS3Storage(bucket, location, endpoint, accessKeyID, secretAccessKey string, secure bool) (*S3Storage, error) {
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
		return nil, errors.Wrapf(err, "cannot check if bucket %q in location %q exits", bucket, location)
	}
	if !exists {
		if err := minioClient.MakeBucket(bucket, location); err != nil {
			return nil, errors.Wrapf(err, "cannot create bucket %q in location %q", bucket, location)
		}
	}

	return &S3Storage{
		bucket:      bucket,
		minioClient: minioClient,
		minioCore:   minioCore,
	}, nil
}

func (s *S3Storage) Stat(p string) (*ObjectInfo, error) {
	oi, err := s.minioClient.StatObject(s.bucket, p, minio.StatObjectOptions{})
	if err != nil {
		merr := minio.ToErrorResponse(err)
		if merr.StatusCode == http.StatusNotFound {
			return nil, ErrNotExist
		}
		return nil, merr
	}

	return &ObjectInfo{Path: p, LastModified: oi.LastModified}, nil
}

func (s *S3Storage) ReadObject(filepath string) (ReadSeekCloser, error) {
	if _, err := s.minioClient.StatObject(s.bucket, filepath, minio.StatObjectOptions{}); err != nil {
		merr := minio.ToErrorResponse(err)
		if merr.StatusCode == http.StatusNotFound {
			return nil, ErrNotExist
		}
		return nil, merr
	}
	return s.minioClient.GetObject(s.bucket, filepath, minio.GetObjectOptions{})
}

func (s *S3Storage) WriteObject(filepath string, data io.Reader, persist bool) error {
	// hack to know the real file size or minio will do this in memory with big memory usage since s3 doesn't support real streaming of unknown sizes
	// TODO(sgotti) wait for minio client to expose an api to provide the max part size so we can remove this
	tmpfile, err := ioutil.TempFile(os.TempDir(), "s3")
	if err != nil {
		return err
	}
	defer tmpfile.Close()
	defer os.Remove(tmpfile.Name())
	size, err := io.Copy(tmpfile, data)
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

func (s *S3Storage) List(prefix, startWith, delimiter string, doneCh <-chan struct{}) <-chan ObjectInfo {
	objectCh := make(chan ObjectInfo, 1)

	if len(delimiter) > 1 {
		objectCh <- ObjectInfo{
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
	go func(objectCh chan<- ObjectInfo) {
		defer close(objectCh)
		// Save continuationToken for next request.
		var continuationToken string
		for {
			// Get list of objects a maximum of 1000 per request.
			result, err := s.minioCore.ListObjectsV2(s.bucket, prefix, continuationToken, false, delimiter, 1000, startWith)
			if err != nil {
				objectCh <- ObjectInfo{
					Err: err,
				}
				return
			}

			// If contents are available loop through and send over channel.
			for _, object := range result.Contents {
				select {
				// Send object content.
				case objectCh <- ObjectInfo{Path: object.Key, LastModified: object.LastModified}:
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
