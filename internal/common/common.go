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

package common

import (
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path"

	errors "golang.org/x/xerrors"
	"github.com/sorintlab/agola/internal/etcd"
	"github.com/sorintlab/agola/internal/objectstorage"
	"github.com/sorintlab/agola/internal/objectstorage/posix"
	"github.com/sorintlab/agola/internal/objectstorage/s3"
	"github.com/sorintlab/agola/internal/services/config"
	"go.uber.org/zap"
)

const (
	StorePrefix = "agola"
)

// WriteFileAtomicFunc atomically writes a file, it achieves this by creating a
// temporary file and then moving it. writeFunc is the func that will write
// data to the file.
// This function is taken from
//   https://github.com/youtube/vitess/blob/master/go/ioutil2/ioutil.go
// Copyright 2012, Google Inc. BSD-license, see licenses/LICENSE-BSD-3-Clause
func WriteFileAtomicFunc(filename string, perm os.FileMode, writeFunc func(f io.Writer) error) error {
	dir, name := path.Split(filename)
	f, err := ioutil.TempFile(dir, name)
	if err != nil {
		return err
	}
	err = writeFunc(f)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if permErr := os.Chmod(f.Name(), perm); err == nil {
		err = permErr
	}
	if err == nil {
		err = os.Rename(f.Name(), filename)
	}
	// Any err should result in full cleanup.
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

// WriteFileAtomic atomically writes a file
func WriteFileAtomic(filename string, data []byte, perm os.FileMode) error {
	return WriteFileAtomicFunc(filename, perm,
		func(f io.Writer) error {
			_, err := f.Write(data)
			return err
		})
}

func NewObjectStorage(c *config.ObjectStorage) (*objectstorage.ObjStorage, error) {
	var (
		err error
		ost objectstorage.Storage
	)

	switch c.Type {
	case config.ObjectStorageTypePosix:
		ost, err = posix.New(c.Path)
		if err != nil {
			return nil, errors.Errorf("failed to create posix object storage: %w", err)
		}
	case config.ObjectStorageTypeS3:
		// minio golang client doesn't accept an url as an endpoint
		endpoint := c.Endpoint
		secure := !c.DisableTLS
		if u, err := url.Parse(c.Endpoint); err == nil {
			endpoint = u.Host
			switch u.Scheme {
			case "https":
				secure = true
			case "http":
				secure = false
			default:
				return nil, errors.Errorf("wrong s3 endpoint scheme %q (must be http or https)", u.Scheme)
			}
		}
		ost, err = s3.New(c.Bucket, c.Location, endpoint, c.AccessKey, c.SecretAccessKey, secure)
		if err != nil {
			return nil, errors.Errorf("failed to create s3 object storage: %w", err)
		}
	}

	return objectstorage.NewObjStorage(ost, "/"), nil
}

func NewEtcd(c *config.Etcd, logger *zap.Logger, prefix string) (*etcd.Store, error) {
	e, err := etcd.New(etcd.Config{
		Logger:        logger,
		Endpoints:     c.Endpoints,
		Prefix:        prefix,
		CertFile:      c.TLSCertFile,
		KeyFile:       c.TLSKeyFile,
		CAFile:        c.TLSCAFile,
		SkipTLSVerify: c.TLSSkipVerify,
	})
	if err != nil {
		return nil, errors.Errorf("failed to create etcd store: %w", err)
	}

	return e, nil
}
