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

package config

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	errors "golang.org/x/xerrors"
)

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name     string
		services []string
		in       string
		err      error
	}{
		{
			name:     "test config for all-base components and executor",
			services: []string{"all-base", "executor"},
			in: `
gateway:
  apiExposedURL: "http://localhost:8000"
  webExposedURL: "http://localhost:8000"
  runserviceURL: "http://localhost:4000"
  configstoreURL: "http://localhost:4002"
  gitserverURL: "http://localhost:4003"

  web:
    listenAddress: ":8000"
  tokenSigning:
    method: hmac
    key: supersecretsigningkey
  adminToken: "admintoken"

scheduler:
  runserviceURL: "http://localhost:4000"

notification:
  webExposedURL: "http://localhost:8000"
  runserviceURL: "http://localhost:4000"
  configstoreURL: "http://localhost:4002"
  etcd:
    endpoints: "http://localhost:2379"

configstore:
  dataDir: /data/agola/configstore
  etcd:
    endpoints: "http://localhost:2379"
  objectStorage:
    type: posix
    path: /agola/configstore/ost
  web:
    listenAddress: ":4002"

runservice:
  #debug: true
  dataDir: /opt/data/agola/runservice
  etcd:
    endpoints: "http://localhost:2379"
  objectStorage:
    type: posix
    path: /agola/runservice/ost
  web:
    listenAddress: ":4000"

executor:
  allowPrivilegedContainers: true
  dataDir: /data/agola/executor
  toolboxPath: ./bin
  runserviceURL: "http://localhost:4000"
  web:
    listenAddress: ":4001"
  activeTasksLimit: 5
  driver:
    type: docker

gitserver:
  dataDir: /data/agola/gitserver
  gatewayURL: "http://localhost:8000"
  web:
    listenAddress: ":4003"`,
		},
		{
			name:     "test config for all-base components",
			services: []string{"all-base"},
			in: `
gateway:
  apiExposedURL: "http://localhost:8000"
  webExposedURL: "http://localhost:8000"
  runserviceURL: "http://localhost:4000"
  configstoreURL: "http://localhost:4002"
  gitserverURL: "http://localhost:4003"

  web:
    listenAddress: ":8000"
  tokenSigning:
    method: hmac
    key: supersecretsigningkey
  adminToken: "admintoken"

scheduler:
  runserviceURL: "http://localhost:4000"

notification:
  webExposedURL: "http://localhost:8000"
  runserviceURL: "http://localhost:4000"
  configstoreURL: "http://localhost:4002"
  etcd:
    endpoints: "http://localhost:2379"

configstore:
  dataDir: /data/agola/configstore
  etcd:
    endpoints: "http://localhost:2379"
  objectStorage:
    type: posix
    path: /agola/configstore/ost
  web:
    listenAddress: ":4002"

runservice:
  dataDir: /data/agola/runservice
  etcd:
    endpoints: "http://localhost:2379"
  objectStorage:
    type: posix
    path: /agola/runservice/ost
  web:
    listenAddress: ":4000"

gitserver:
  dataDir: /data/agola/gitserver
  gatewayURL: "http://localhost:8000"
  web:
    listenAddress: ":4003"`,
		},
		{
			name:     "test config for gateway, scheduler and notification",
			services: []string{"gateway", "scheduler", "notification"},
			in: `
gateway:
  apiExposedURL: "http://localhost:8000"
  webExposedURL: "http://localhost:8000"
  runserviceURL: "http://localhost:4000"
  configstoreURL: "http://localhost:4002"
  gitserverURL: "http://localhost:4003"

  web:
    listenAddress: ":8000"
  tokenSigning:
    method: hmac
    key: supersecretsigningkey
  adminToken: "admintoken"

scheduler:
  runserviceURL: "http://localhost:4000"

notification:
  webExposedURL: "http://localhost:8000"
  runserviceURL: "http://localhost:4000"
  configstoreURL: "http://localhost:4002"
  etcd:
    endpoints: "http://localhost:2379"

configstore:
  dataDir: 

runservice:
  dataDir: 

gitserver:
  dataDir:`,
		},
		{
			name:     "test config for gateway, scheduler, notification and gitserver without dataDir",
			services: []string{"gateway", "scheduler", "notification", "gitserver"},
			in: `
gateway:
  apiExposedURL: "http://localhost:8000"
  webExposedURL: "http://localhost:8000"
  runserviceURL: "http://localhost:4000"
  configstoreURL: "http://localhost:4002"
  gitserverURL: "http://localhost:4003"

  web:
    listenAddress: ":8000"
  tokenSigning:
    method: hmac
    key: supersecretsigningkey
  adminToken: "admintoken"

scheduler:
  runserviceURL: "http://localhost:4000"

notification:
  webExposedURL: "http://localhost:8000"
  runserviceURL: "http://localhost:4000"
  configstoreURL: "http://localhost:4002"
  etcd:
    endpoints: "http://localhost:2379"

configstore:
  dataDir:

runservice:
  dataDir:

gitserver:
  dataDir:`,
			err: errors.Errorf("git server dataDir is empty"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := ioutil.TempDir("", "ParseConfig")
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			defer os.RemoveAll(dir)

			content := []byte(tt.in)
			err = ioutil.WriteFile(path.Join(dir, "config.yml"), content, 0644)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if _, err := Parse(path.Join(dir, "config.yml"), tt.services); err != nil {
				if tt.err == nil {
					t.Fatalf("got error: %v, expected no error", err)
				}
				if err.Error() != tt.err.Error() {
					t.Fatalf("got error: %v, want error: %v", err, tt.err)
				}
			} else {
				if tt.err != nil {
					t.Fatalf("got nil error, want error: %v", tt.err)
				}
			}
		})
	}
}
