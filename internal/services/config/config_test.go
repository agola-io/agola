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
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/sorintlab/errors"
)

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name     string
		services []string
		in       string
		out      *Config
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
  cookieSigning:
    key: supersecretsigningkey
  adminToken: "admintoken"

scheduler:
  runserviceURL: "http://localhost:4000"

notification:
  webExposedURL: "http://localhost:8000"
  runserviceURL: "http://localhost:4000"
  configstoreURL: "http://localhost:4002"

configstore:
  dataDir: /data/agola/configstore
  db:
    type: sqlite3
    connString: /data/agola/configstore/db
  objectStorage:
    type: posix
    path: /agola/configstore/ost
  web:
    listenAddress: ":4002"

runservice:
  #debug: true
  dataDir: /data/agola/runservice
  db:
    type: sqlite3
    connString: /data/agola/runservice/db
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
  web:
    listenAddress: ":4003"
`,
			out: &Config{
				ID: "agola",
				Gateway: Gateway{
					APIExposedURL:                "http://localhost:8000",
					WebExposedURL:                "http://localhost:8000",
					RunserviceURL:                "http://localhost:4000",
					ConfigstoreURL:               "http://localhost:4002",
					GitserverURL:                 "http://localhost:4003",
					Web:                          Web{ListenAddress: ":8000"},
					TokenSigning:                 TokenSigning{Duration: 12 * time.Hour, Method: "hmac", Key: "supersecretsigningkey"},
					CookieSigning:                CookieSigning{Duration: 12 * time.Hour, Key: "supersecretsigningkey"},
					AdminToken:                   "admintoken",
					OrganizationMemberAddingMode: defaultOrganizationMemberAddingMode,
				},
				Scheduler: Scheduler{RunserviceURL: "http://localhost:4000"},
				Notification: Notification{
					WebExposedURL:  "http://localhost:8000",
					RunserviceURL:  "http://localhost:4000",
					ConfigstoreURL: "http://localhost:4002",
				},
				Runservice: Runservice{
					DataDir:                    "/data/agola/runservice",
					DB:                         DB{Type: "sqlite3", ConnString: "/data/agola/runservice/db"},
					Web:                        Web{ListenAddress: ":4000"},
					ObjectStorage:              ObjectStorage{Type: "posix", Path: "/agola/runservice/ost"},
					RunCacheExpireInterval:     7 * 24 * time.Hour,
					RunWorkspaceExpireInterval: 7 * 24 * time.Hour,
					RunLogExpireInterval:       30 * 24 * time.Hour,
				},
				Executor: Executor{
					DataDir:                   "/data/agola/executor",
					RunserviceURL:             "http://localhost:4000",
					ToolboxPath:               "./bin",
					Web:                       Web{ListenAddress: ":4001"},
					Driver:                    Driver{Type: "docker"},
					InitImage:                 InitImage{Image: "busybox:stable"},
					ActiveTasksLimit:          5,
					AllowPrivilegedContainers: true,
				},
				Configstore: Configstore{
					DataDir:       "/data/agola/configstore",
					DB:            DB{Type: "sqlite3", ConnString: "/data/agola/configstore/db"},
					Web:           Web{ListenAddress: ":4002"},
					ObjectStorage: ObjectStorage{Type: "posix", Path: "/agola/configstore/ost"},
				},
				Gitserver: Gitserver{
					DataDir:                      "/data/agola/gitserver",
					Web:                          Web{ListenAddress: ":4003"},
					RepositoryCleanupInterval:    24 * time.Hour,
					RepositoryRefsExpireInterval: 30 * 24 * time.Hour,
				},
			},
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
  cookieSigning:
    key: supersecretsigningkey
  adminToken: "admintoken"

scheduler:
  runserviceURL: "http://localhost:4000"

notification:
  webExposedURL: "http://localhost:8000"
  runserviceURL: "http://localhost:4000"
  configstoreURL: "http://localhost:4002"

configstore:
  dataDir: /data/agola/configstore
  db:
    type: sqlite3
    connString: /data/agola/configstore/db
  objectStorage:
    type: posix
    path: /agola/configstore/ost
  web:
    listenAddress: ":4002"

runservice:
  dataDir: /data/agola/runservice
  db:
    type: sqlite3
    connString: /data/agola/runservice/db
  objectStorage:
    type: posix
    path: /agola/runservice/ost
  web:
    listenAddress: ":4000"

gitserver:
  dataDir: /data/agola/gitserver
  web:
    listenAddress: ":4003"
    `,
			out: &Config{
				ID: "agola",
				Gateway: Gateway{
					APIExposedURL:                "http://localhost:8000",
					WebExposedURL:                "http://localhost:8000",
					RunserviceURL:                "http://localhost:4000",
					ConfigstoreURL:               "http://localhost:4002",
					GitserverURL:                 "http://localhost:4003",
					Web:                          Web{ListenAddress: ":8000"},
					TokenSigning:                 TokenSigning{Duration: 12 * time.Hour, Method: "hmac", Key: "supersecretsigningkey"},
					CookieSigning:                CookieSigning{Duration: 12 * time.Hour, Key: "supersecretsigningkey"},
					AdminToken:                   "admintoken",
					OrganizationMemberAddingMode: defaultOrganizationMemberAddingMode,
				},
				Scheduler: Scheduler{RunserviceURL: "http://localhost:4000"},
				Notification: Notification{
					WebExposedURL:  "http://localhost:8000",
					RunserviceURL:  "http://localhost:4000",
					ConfigstoreURL: "http://localhost:4002",
				},
				Runservice: Runservice{
					DataDir:                    "/data/agola/runservice",
					DB:                         DB{Type: "sqlite3", ConnString: "/data/agola/runservice/db"},
					Web:                        Web{ListenAddress: ":4000"},
					ObjectStorage:              ObjectStorage{Type: "posix", Path: "/agola/runservice/ost"},
					RunCacheExpireInterval:     7 * 24 * time.Hour,
					RunWorkspaceExpireInterval: 7 * 24 * time.Hour,
					RunLogExpireInterval:       30 * 24 * time.Hour,
				},
				Executor: Executor{
					InitImage: InitImage{
						Image: "busybox:stable",
					},
					ActiveTasksLimit: 2,
				},
				Configstore: Configstore{
					DataDir:       "/data/agola/configstore",
					DB:            DB{Type: "sqlite3", ConnString: "/data/agola/configstore/db"},
					Web:           Web{ListenAddress: ":4002"},
					ObjectStorage: ObjectStorage{Type: "posix", Path: "/agola/configstore/ost"},
				},
				Gitserver: Gitserver{
					DataDir:                      "/data/agola/gitserver",
					Web:                          Web{ListenAddress: ":4003"},
					RepositoryCleanupInterval:    24 * time.Hour,
					RepositoryRefsExpireInterval: 30 * 24 * time.Hour,
				},
			},
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
  cookieSigning:
    key: supersecretsigningkey
  adminToken: "admintoken"

scheduler:
  runserviceURL: "http://localhost:4000"

notification:
  webExposedURL: "http://localhost:8000"
  runserviceURL: "http://localhost:4000"
  configstoreURL: "http://localhost:4002"

configstore:
  dataDir:

runservice:
  dataDir:

gitserver:
  dataDir:
`,
			out: &Config{
				ID: "agola",
				Gateway: Gateway{
					APIExposedURL:                "http://localhost:8000",
					WebExposedURL:                "http://localhost:8000",
					RunserviceURL:                "http://localhost:4000",
					ConfigstoreURL:               "http://localhost:4002",
					GitserverURL:                 "http://localhost:4003",
					Web:                          Web{ListenAddress: ":8000"},
					TokenSigning:                 TokenSigning{Duration: 12 * time.Hour, Method: "hmac", Key: "supersecretsigningkey"},
					CookieSigning:                CookieSigning{Duration: 12 * time.Hour, Key: "supersecretsigningkey"},
					AdminToken:                   "admintoken",
					OrganizationMemberAddingMode: defaultOrganizationMemberAddingMode,
				},
				Scheduler: Scheduler{RunserviceURL: "http://localhost:4000"},
				Notification: Notification{
					WebExposedURL:  "http://localhost:8000",
					RunserviceURL:  "http://localhost:4000",
					ConfigstoreURL: "http://localhost:4002",
				},
				Runservice: Runservice{
					RunCacheExpireInterval:     7 * 24 * time.Hour,
					RunWorkspaceExpireInterval: 7 * 24 * time.Hour,
					RunLogExpireInterval:       30 * 24 * time.Hour,
				},
				Executor: Executor{InitImage: InitImage{Image: "busybox:stable"}, ActiveTasksLimit: 2},
				Gitserver: Gitserver{
					RepositoryCleanupInterval:    24 * time.Hour,
					RepositoryRefsExpireInterval: 30 * 24 * time.Hour,
				},
			},
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
  cookieSigning:
    key: supersecretsigningkey
  adminToken: "admintoken"

scheduler:
  runserviceURL: "http://localhost:4000"

notification:
  webExposedURL: "http://localhost:8000"
  runserviceURL: "http://localhost:4000"
  configstoreURL: "http://localhost:4002"

configstore:
  dataDir:

runservice:
  dataDir:

gitserver:
  dataDir:
`,
			err: errors.Errorf("git server dataDir is empty"),
		},

		{
			name:     "test config with global urls",
			services: []string{"all-base", "executor"},
			in: `
apiExposedURL: "http://localhost:8000"
webExposedURL: "http://localhost:8000"
runserviceURL: "http://localhost:4000"
configstoreURL: "http://localhost:4002"
gitserverURL: "http://localhost:4003"

gateway:
  web:
    listenAddress: ":8000"
  tokenSigning:
    method: hmac
    key: supersecretsigningkey
  cookieSigning:
    key: supersecretsigningkey
  adminToken: "admintoken"

scheduler:

notification:

configstore:
  dataDir: /data/agola/configstore
  db:
    type: sqlite3
    connString: /data/agola/configstore/db
  objectStorage:
    type: posix
    path: /agola/configstore/ost
  web:
    listenAddress: ":4002"

runservice:
  #debug: true
  dataDir: /data/agola/runservice
  db:
    type: sqlite3
    connString: /data/agola/runservice/db
  objectStorage:
    type: posix
    path: /agola/runservice/ost
  web:
    listenAddress: ":4000"

executor:
  allowPrivilegedContainers: true
  dataDir: /data/agola/executor
  toolboxPath: ./bin
  web:
    listenAddress: ":4001"
  activeTasksLimit: 5
  driver:
    type: docker

gitserver:
  dataDir: /data/agola/gitserver
  web:
    listenAddress: ":4003"
`,
			out: &Config{
				ID:             "agola",
				APIExposedURL:  "http://localhost:8000",
				WebExposedURL:  "http://localhost:8000",
				RunserviceURL:  "http://localhost:4000",
				ConfigstoreURL: "http://localhost:4002",
				GitserverURL:   "http://localhost:4003",
				Gateway: Gateway{
					APIExposedURL:                "http://localhost:8000",
					WebExposedURL:                "http://localhost:8000",
					RunserviceURL:                "http://localhost:4000",
					ConfigstoreURL:               "http://localhost:4002",
					GitserverURL:                 "http://localhost:4003",
					Web:                          Web{ListenAddress: ":8000"},
					TokenSigning:                 TokenSigning{Duration: 12 * time.Hour, Method: "hmac", Key: "supersecretsigningkey"},
					CookieSigning:                CookieSigning{Duration: 12 * time.Hour, Key: "supersecretsigningkey"},
					AdminToken:                   "admintoken",
					OrganizationMemberAddingMode: defaultOrganizationMemberAddingMode,
				},
				Scheduler: Scheduler{RunserviceURL: "http://localhost:4000"},
				Notification: Notification{
					WebExposedURL:  "http://localhost:8000",
					RunserviceURL:  "http://localhost:4000",
					ConfigstoreURL: "http://localhost:4002",
				},
				Runservice: Runservice{
					DataDir:                    "/data/agola/runservice",
					DB:                         DB{Type: "sqlite3", ConnString: "/data/agola/runservice/db"},
					Web:                        Web{ListenAddress: ":4000"},
					ObjectStorage:              ObjectStorage{Type: "posix", Path: "/agola/runservice/ost"},
					RunCacheExpireInterval:     7 * 24 * time.Hour,
					RunWorkspaceExpireInterval: 7 * 24 * time.Hour,
					RunLogExpireInterval:       30 * 24 * time.Hour,
				},
				Executor: Executor{
					DataDir:                   "/data/agola/executor",
					RunserviceURL:             "http://localhost:4000",
					ToolboxPath:               "./bin",
					Web:                       Web{ListenAddress: ":4001"},
					Driver:                    Driver{Type: "docker"},
					InitImage:                 InitImage{Image: "busybox:stable"},
					ActiveTasksLimit:          5,
					AllowPrivilegedContainers: true,
				},
				Configstore: Configstore{
					DataDir:       "/data/agola/configstore",
					DB:            DB{Type: "sqlite3", ConnString: "/data/agola/configstore/db"},
					Web:           Web{ListenAddress: ":4002"},
					ObjectStorage: ObjectStorage{Type: "posix", Path: "/agola/configstore/ost"},
				},
				Gitserver: Gitserver{
					DataDir:                      "/data/agola/gitserver",
					Web:                          Web{ListenAddress: ":4003"},
					RepositoryCleanupInterval:    24 * time.Hour,
					RepositoryRefsExpireInterval: 30 * 24 * time.Hour,
				},
			},
		},
		{
			name:     "test config with global internal services token",
			services: []string{"all-base", "executor"},
			in: `
apiExposedURL: "http://localhost:8000"
webExposedURL: "http://localhost:8000"
runserviceURL: "http://localhost:4000"
configstoreURL: "http://localhost:4002"
gitserverURL: "http://localhost:4003"

internalServicesAPIToken: "internalservicesapitoken"

gateway:
  web:
    listenAddress: ":8000"
  tokenSigning:
    method: hmac
    key: supersecretsigningkey
  cookieSigning:
    key: supersecretsigningkey
  adminToken: "admintoken"

scheduler:

notification:

configstore:
  dataDir: /data/agola/configstore
  db:
    type: sqlite3
    connString: /data/agola/configstore/db
  objectStorage:
    type: posix
    path: /agola/configstore/ost
  web:
    listenAddress: ":4002"

runservice:
  #debug: true
  dataDir: /data/agola/runservice
  db:
    type: sqlite3
    connString: /data/agola/runservice/db
  objectStorage:
    type: posix
    path: /agola/runservice/ost
  web:
    listenAddress: ":4000"

executor:
  allowPrivilegedContainers: true
  dataDir: /data/agola/executor
  toolboxPath: ./bin
  web:
    listenAddress: ":4001"
  activeTasksLimit: 5
  driver:
    type: docker

gitserver:
  dataDir: /data/agola/gitserver
  web:
    listenAddress: ":4003"
`,
			out: &Config{
				ID:             "agola",
				APIExposedURL:  "http://localhost:8000",
				WebExposedURL:  "http://localhost:8000",
				RunserviceURL:  "http://localhost:4000",
				ConfigstoreURL: "http://localhost:4002",
				GitserverURL:   "http://localhost:4003",

				InternalServicesAPIToken: "internalservicesapitoken",
				RunserviceAPIToken:       "internalservicesapitoken",
				ExecutorAPIToken:         "internalservicesapitoken",
				ConfigstoreAPIToken:      "internalservicesapitoken",
				GitserverAPIToken:        "internalservicesapitoken",

				Gateway: Gateway{
					APIExposedURL:                "http://localhost:8000",
					WebExposedURL:                "http://localhost:8000",
					RunserviceURL:                "http://localhost:4000",
					RunserviceAPIToken:           "internalservicesapitoken",
					ConfigstoreURL:               "http://localhost:4002",
					ConfigstoreAPIToken:          "internalservicesapitoken",
					GitserverURL:                 "http://localhost:4003",
					GitserverAPIToken:            "internalservicesapitoken",
					Web:                          Web{ListenAddress: ":8000"},
					TokenSigning:                 TokenSigning{Duration: 12 * time.Hour, Method: "hmac", Key: "supersecretsigningkey"},
					CookieSigning:                CookieSigning{Duration: 12 * time.Hour, Key: "supersecretsigningkey"},
					AdminToken:                   "admintoken",
					OrganizationMemberAddingMode: defaultOrganizationMemberAddingMode,
				},
				Scheduler: Scheduler{
					RunserviceURL:      "http://localhost:4000",
					RunserviceAPIToken: "internalservicesapitoken",
				},
				Notification: Notification{
					WebExposedURL:       "http://localhost:8000",
					RunserviceURL:       "http://localhost:4000",
					RunserviceAPIToken:  "internalservicesapitoken",
					ConfigstoreURL:      "http://localhost:4002",
					ConfigstoreAPIToken: "internalservicesapitoken",
				},
				Runservice: Runservice{
					DataDir:                    "/data/agola/runservice",
					DB:                         DB{Type: "sqlite3", ConnString: "/data/agola/runservice/db"},
					Web:                        Web{ListenAddress: ":4000"},
					APIToken:                   "internalservicesapitoken",
					ExecutorAPIToken:           "internalservicesapitoken",
					ObjectStorage:              ObjectStorage{Type: "posix", Path: "/agola/runservice/ost"},
					RunCacheExpireInterval:     7 * 24 * time.Hour,
					RunWorkspaceExpireInterval: 7 * 24 * time.Hour,
					RunLogExpireInterval:       30 * 24 * time.Hour,
				},
				Executor: Executor{
					DataDir:                   "/data/agola/executor",
					RunserviceURL:             "http://localhost:4000",
					RunserviceAPIToken:        "internalservicesapitoken",
					ToolboxPath:               "./bin",
					Web:                       Web{ListenAddress: ":4001"},
					APIToken:                  "internalservicesapitoken",
					Driver:                    Driver{Type: "docker"},
					InitImage:                 InitImage{Image: "busybox:stable"},
					ActiveTasksLimit:          5,
					AllowPrivilegedContainers: true,
				},
				Configstore: Configstore{
					DataDir:       "/data/agola/configstore",
					DB:            DB{Type: "sqlite3", ConnString: "/data/agola/configstore/db"},
					Web:           Web{ListenAddress: ":4002"},
					APIToken:      "internalservicesapitoken",
					ObjectStorage: ObjectStorage{Type: "posix", Path: "/agola/configstore/ost"},
				},
				Gitserver: Gitserver{
					DataDir:                      "/data/agola/gitserver",
					Web:                          Web{ListenAddress: ":4003"},
					APIToken:                     "internalservicesapitoken",
					RepositoryCleanupInterval:    24 * time.Hour,
					RepositoryRefsExpireInterval: 30 * 24 * time.Hour,
				},
			},
		},
		{
			name:     "test config with global different internal services token",
			services: []string{"all-base", "executor"},
			in: `
apiExposedURL: "http://localhost:8000"
webExposedURL: "http://localhost:8000"
runserviceURL: "http://localhost:4000"
configstoreURL: "http://localhost:4002"
gitserverURL: "http://localhost:4003"

internalServicesAPIToken: "internalservicesapitoken" # should not be used since custom token are defined for every service
runserviceAPIToken: "runserviceapitoken"
executorAPIToken: "executorapitoken"
configstoreAPIToken: "configstoreapitoken"
gitserverAPIToken: "gitserverapitoken"

gateway:
  web:
    listenAddress: ":8000"
  tokenSigning:
    method: hmac
    key: supersecretsigningkey
  cookieSigning:
    key: supersecretsigningkey
  adminToken: "admintoken"

scheduler:

notification:

configstore:
  dataDir: /data/agola/configstore
  db:
    type: sqlite3
    connString: /data/agola/configstore/db
  objectStorage:
    type: posix
    path: /agola/configstore/ost
  web:
    listenAddress: ":4002"

runservice:
  #debug: true
  dataDir: /data/agola/runservice
  db:
    type: sqlite3
    connString: /data/agola/runservice/db
  objectStorage:
    type: posix
    path: /agola/runservice/ost
  web:
    listenAddress: ":4000"

executor:
  allowPrivilegedContainers: true
  dataDir: /data/agola/executor
  toolboxPath: ./bin
  web:
    listenAddress: ":4001"
  activeTasksLimit: 5
  driver:
    type: docker

gitserver:
  dataDir: /data/agola/gitserver
  web:
    listenAddress: ":4003"
`,
			out: &Config{
				ID:             "agola",
				APIExposedURL:  "http://localhost:8000",
				WebExposedURL:  "http://localhost:8000",
				RunserviceURL:  "http://localhost:4000",
				ConfigstoreURL: "http://localhost:4002",
				GitserverURL:   "http://localhost:4003",

				InternalServicesAPIToken: "internalservicesapitoken",
				RunserviceAPIToken:       "runserviceapitoken",
				ExecutorAPIToken:         "executorapitoken",
				ConfigstoreAPIToken:      "configstoreapitoken",
				GitserverAPIToken:        "gitserverapitoken",

				Gateway: Gateway{
					APIExposedURL:                "http://localhost:8000",
					WebExposedURL:                "http://localhost:8000",
					RunserviceURL:                "http://localhost:4000",
					RunserviceAPIToken:           "runserviceapitoken",
					ConfigstoreURL:               "http://localhost:4002",
					ConfigstoreAPIToken:          "configstoreapitoken",
					GitserverURL:                 "http://localhost:4003",
					GitserverAPIToken:            "gitserverapitoken",
					Web:                          Web{ListenAddress: ":8000"},
					TokenSigning:                 TokenSigning{Duration: 12 * time.Hour, Method: "hmac", Key: "supersecretsigningkey"},
					CookieSigning:                CookieSigning{Duration: 12 * time.Hour, Key: "supersecretsigningkey"},
					AdminToken:                   "admintoken",
					OrganizationMemberAddingMode: defaultOrganizationMemberAddingMode,
				},
				Scheduler: Scheduler{
					RunserviceURL:      "http://localhost:4000",
					RunserviceAPIToken: "runserviceapitoken",
				},
				Notification: Notification{
					WebExposedURL:       "http://localhost:8000",
					RunserviceURL:       "http://localhost:4000",
					RunserviceAPIToken:  "runserviceapitoken",
					ConfigstoreURL:      "http://localhost:4002",
					ConfigstoreAPIToken: "configstoreapitoken",
				},
				Runservice: Runservice{
					DataDir:                    "/data/agola/runservice",
					DB:                         DB{Type: "sqlite3", ConnString: "/data/agola/runservice/db"},
					Web:                        Web{ListenAddress: ":4000"},
					APIToken:                   "runserviceapitoken",
					ExecutorAPIToken:           "executorapitoken",
					ObjectStorage:              ObjectStorage{Type: "posix", Path: "/agola/runservice/ost"},
					RunCacheExpireInterval:     7 * 24 * time.Hour,
					RunWorkspaceExpireInterval: 7 * 24 * time.Hour,
					RunLogExpireInterval:       30 * 24 * time.Hour,
				},
				Executor: Executor{
					DataDir:                   "/data/agola/executor",
					RunserviceURL:             "http://localhost:4000",
					RunserviceAPIToken:        "runserviceapitoken",
					ToolboxPath:               "./bin",
					Web:                       Web{ListenAddress: ":4001"},
					APIToken:                  "executorapitoken",
					Driver:                    Driver{Type: "docker"},
					InitImage:                 InitImage{Image: "busybox:stable"},
					ActiveTasksLimit:          5,
					AllowPrivilegedContainers: true,
				},
				Configstore: Configstore{
					DataDir:       "/data/agola/configstore",
					DB:            DB{Type: "sqlite3", ConnString: "/data/agola/configstore/db"},
					Web:           Web{ListenAddress: ":4002"},
					APIToken:      "configstoreapitoken",
					ObjectStorage: ObjectStorage{Type: "posix", Path: "/agola/configstore/ost"},
				},
				Gitserver: Gitserver{
					DataDir:                      "/data/agola/gitserver",
					Web:                          Web{ListenAddress: ":4003"},
					APIToken:                     "gitserverapitoken",
					RepositoryCleanupInterval:    24 * time.Hour,
					RepositoryRefsExpireInterval: 30 * 24 * time.Hour,
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			content := []byte(tt.in)
			err := os.WriteFile(path.Join(dir, "config.yml"), content, 0644)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			c, err := Parse(path.Join(dir, "config.yml"), tt.services)
			if err != nil {
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

				if diff := cmp.Diff(tt.out, c); diff != "" {
					t.Errorf("config mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
