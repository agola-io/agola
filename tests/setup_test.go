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

package tests

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/configstore"
	"agola.io/agola/internal/services/executor"
	"agola.io/agola/internal/services/gateway"
	"agola.io/agola/internal/services/gitserver"
	"agola.io/agola/internal/services/notification"
	rsscheduler "agola.io/agola/internal/services/runservice"
	"agola.io/agola/internal/services/scheduler"
	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"
	rstypes "agola.io/agola/services/runservice/types"

	"code.gitea.io/sdk/gitea"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	errors "golang.org/x/xerrors"
	"gopkg.in/src-d/go-billy.v4/memfs"
	"gopkg.in/src-d/go-billy.v4/osfs"
	"gopkg.in/src-d/go-git.v4"
	gitconfig "gopkg.in/src-d/go-git.v4/config"
	"gopkg.in/src-d/go-git.v4/plumbing"
	"gopkg.in/src-d/go-git.v4/plumbing/cache"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
	"gopkg.in/src-d/go-git.v4/storage/filesystem"
	"gopkg.in/src-d/go-git.v4/storage/memory"
)

const (
	giteaUser01 = "user01"
	giteaUser02 = "user02"

	agolaUser01 = "user01"
)

type ConfigFormat string

const (
	// ConfigFormatJSON handles both json or yaml format (since json is a subset of yaml)
	ConfigFormatJSON     ConfigFormat = "json"
	ConfigFormatJsonnet  ConfigFormat = "jsonnet"
	ConfigFormatStarlark ConfigFormat = "starlark"
)

func setupEtcd(t *testing.T, logger *zap.Logger, dir string) *testutil.TestEmbeddedEtcd {
	tetcd, err := testutil.NewTestEmbeddedEtcd(t, logger, dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := tetcd.Start(); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := tetcd.WaitUp(30 * time.Second); err != nil {
		t.Fatalf("error waiting on etcd up: %v", err)
	}
	return tetcd
}

func shutdownEtcd(tetcd *testutil.TestEmbeddedEtcd) {
	if tetcd.Etcd != nil {
		_ = tetcd.Kill()
	}
}

func setupGitea(t *testing.T, dir, dockerBridgeAddress string) *testutil.TestGitea {
	tgitea, err := testutil.NewTestGitea(t, dir, dockerBridgeAddress)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := tgitea.Start(); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// wait for gitea ready
	err = testutil.Wait(30*time.Second, func() (bool, error) {
		cmd := exec.Command(tgitea.GiteaPath, "admin", "create-user", "--name", giteaUser01, "--email", giteaUser01+"@example.com", "--password", "password", "--admin", "--config", tgitea.ConfigPath)
		// just retry until no error
		if err := cmd.Run(); err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	giteaAPIURL := fmt.Sprintf("http://%s:%s", tgitea.HTTPListenAddress, tgitea.HTTPPort)
	giteaClient := gitea.NewClient(giteaAPIURL, "")

	// Wait for gitea api to be ready
	err = testutil.Wait(30*time.Second, func() (bool, error) {
		giteaClient.SetBasicAuth(giteaUser01, "password")
		if _, err := giteaClient.ListAccessTokens(gitea.ListAccessTokensOptions{}); err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	return tgitea
}

func shutdownGitea(tgitea *testutil.TestGitea) {
	tgitea.Kill()
}

func startAgola(ctx context.Context, t *testing.T, logger *zap.Logger, dir string, c *config.Config) (<-chan error, error) {
	rs, err := rsscheduler.NewRunservice(ctx, logger, &c.Runservice)
	if err != nil {
		return nil, errors.Errorf("failed to start run service scheduler: %w", err)
	}

	ex, err := executor.NewExecutor(ctx, logger, &c.Executor)
	if err != nil {
		return nil, errors.Errorf("failed to start run service executor: %w", err)
	}

	cs, err := configstore.NewConfigstore(ctx, logger, &c.Configstore)
	if err != nil {
		return nil, errors.Errorf("failed to start config store: %w", err)
	}

	sched, err := scheduler.NewScheduler(ctx, logger, &c.Scheduler)
	if err != nil {
		return nil, errors.Errorf("failed to start scheduler: %w", err)
	}

	ns, err := notification.NewNotificationService(ctx, logger, c)
	if err != nil {
		return nil, errors.Errorf("failed to start notification service: %w", err)
	}

	gw, err := gateway.NewGateway(ctx, logger, c)
	if err != nil {
		return nil, errors.Errorf("failed to start gateway: %w", err)
	}

	gs, err := gitserver.NewGitserver(ctx, logger, &c.Gitserver)
	if err != nil {
		return nil, errors.Errorf("failed to start git server: %w", err)
	}

	errCh := make(chan error)

	go func() { errCh <- rs.Run(ctx) }()
	go func() { errCh <- ex.Run(ctx) }()
	go func() { errCh <- cs.Run(ctx) }()
	go func() { errCh <- sched.Run(ctx) }()
	go func() { errCh <- ns.Run(ctx) }()
	go func() { errCh <- gw.Run(ctx) }()
	go func() { errCh <- gs.Run(ctx) }()

	// TODO(sgotti) find a better way to test that all is ready instead of sleeping
	time.Sleep(5 * time.Second)

	return errCh, nil
}

func setup(ctx context.Context, t *testing.T, dir string) (*testutil.TestEmbeddedEtcd, *testutil.TestGitea, *config.Config) {
	logger := zaptest.NewLogger(t, zaptest.Level(zap.InfoLevel))

	dockerBridgeAddress := os.Getenv("DOCKER_BRIDGE_ADDRESS")
	if dockerBridgeAddress == "" {
		dockerBridgeAddress = "172.17.0.1"
	}
	agolaBinDir := os.Getenv("AGOLA_BIN_DIR")
	if agolaBinDir == "" {
		t.Fatalf("env var AGOLA_BIN_DIR is undefined")
	}

	c := &config.Config{
		ID: "agola",
		Gateway: config.Gateway{
			Debug:          false,
			APIExposedURL:  "",
			WebExposedURL:  "",
			RunserviceURL:  "",
			ConfigstoreURL: "",
			GitserverURL:   "",
			Web: config.Web{
				ListenAddress: "",
				TLS:           false,
			},
			TokenSigning: config.TokenSigning{
				Duration: 12 * time.Hour,
				Method:   "hmac",
				Key:      "supersecretsigningkey",
			},
			AdminToken: "admintoken",
		},
		Scheduler: config.Scheduler{
			Debug:         false,
			RunserviceURL: "",
		},
		Notification: config.Notification{
			Debug:          false,
			WebExposedURL:  "",
			RunserviceURL:  "",
			ConfigstoreURL: "",
			Etcd: config.Etcd{
				Endpoints: "",
			},
		},
		Runservice: config.Runservice{
			Debug:   false,
			DataDir: filepath.Join(dir, "runservice"),
			Web: config.Web{
				ListenAddress: ":4000",
				TLS:           false,
			},
			Etcd: config.Etcd{
				Endpoints: "",
			},
			ObjectStorage: config.ObjectStorage{
				Type: "posix",
				Path: filepath.Join(dir, "runservice/ost"),
			},
			RunCacheExpireInterval: 604800000000000,
		},
		Executor: config.Executor{
			Debug:         false,
			DataDir:       filepath.Join(dir, "executor"),
			RunserviceURL: "",
			ToolboxPath:   agolaBinDir,
			Web: config.Web{
				ListenAddress: ":4001",
				TLS:           false,
			},
			Driver: config.Driver{
				Type: "docker",
			},
			Labels:           map[string]string{},
			ActiveTasksLimit: 2,
		},
		Configstore: config.Configstore{
			Debug:   false,
			DataDir: filepath.Join(dir, "configstore"),
			Web: config.Web{
				ListenAddress: ":4002",
				TLS:           false,
			},
			Etcd: config.Etcd{
				Endpoints: "",
			},
			ObjectStorage: config.ObjectStorage{
				Type: "posix",
				Path: filepath.Join(dir, "configstore/ost"),
			},
		},
		Gitserver: config.Gitserver{
			Debug:   false,
			DataDir: filepath.Join(dir, "gitserver"),
			Web: config.Web{
				ListenAddress: ":4003",
				TLS:           false,
			},
			Etcd: config.Etcd{
				Endpoints: "",
			},
		},
	}

	tgitea := setupGitea(t, dir, dockerBridgeAddress)

	etcdDir := filepath.Join(dir, "etcd")
	tetcd := setupEtcd(t, logger, etcdDir)

	c.Runservice.Etcd.Endpoints = tetcd.Endpoint
	c.Configstore.Etcd.Endpoints = tetcd.Endpoint

	_, gwPort, err := testutil.GetFreePort(true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_, csPort, err := testutil.GetFreePort(true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_, rsPort, err := testutil.GetFreePort(true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_, exPort, err := testutil.GetFreePort(true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	listenAddress, gitServerPort, err := testutil.GetFreePort(true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	gwURL := fmt.Sprintf("http://%s:%s", dockerBridgeAddress, gwPort)
	csURL := fmt.Sprintf("http://%s:%s", listenAddress, csPort)
	rsURL := fmt.Sprintf("http://%s:%s", listenAddress, rsPort)
	gitServerURL := fmt.Sprintf("http://%s:%s", dockerBridgeAddress, gitServerPort)

	c.Gateway.Web.ListenAddress = fmt.Sprintf("%s:%s", dockerBridgeAddress, gwPort)
	c.Configstore.Web.ListenAddress = fmt.Sprintf("%s:%s", listenAddress, csPort)
	c.Runservice.Web.ListenAddress = fmt.Sprintf("%s:%s", listenAddress, rsPort)
	c.Executor.Web.ListenAddress = fmt.Sprintf("%s:%s", listenAddress, exPort)
	c.Gitserver.Web.ListenAddress = fmt.Sprintf("%s:%s", dockerBridgeAddress, gitServerPort)

	c.Gateway.APIExposedURL = gwURL
	c.Gateway.WebExposedURL = gwURL
	c.Gateway.RunserviceURL = rsURL
	c.Gateway.ConfigstoreURL = csURL
	c.Gateway.GitserverURL = gitServerURL

	c.Scheduler.RunserviceURL = rsURL

	c.Notification.WebExposedURL = gwURL
	c.Notification.RunserviceURL = rsURL
	c.Notification.ConfigstoreURL = csURL

	c.Executor.RunserviceURL = rsURL

	errCh, err := startAgola(ctx, t, logger, dir, c)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	go func() {
		err := <-errCh
		if err != nil {
			panic(fmt.Errorf("agola component returned error: %+v", err))
		}
	}()

	return tetcd, tgitea, c
}

func TestCreateLinkedAccount(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tetcd, tgitea, c := setup(ctx, t, dir)
	defer shutdownGitea(tgitea)
	defer shutdownEtcd(tetcd)

	createLinkedAccount(ctx, t, tgitea, c)
}

func createAgolaUserToken(ctx context.Context, t *testing.T, c *config.Config) string {
	gwClient := gwclient.NewClient(c.Gateway.APIExposedURL, "admintoken")
	token, _, err := gwClient.CreateUserToken(ctx, agolaUser01, &gwapitypes.CreateUserTokenRequest{TokenName: "token01"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	t.Logf("created agola user token: %s", token.Token)

	return token.Token
}

func createLinkedAccount(ctx context.Context, t *testing.T, tgitea *testutil.TestGitea, c *config.Config) (string, string) {
	giteaAPIURL := fmt.Sprintf("http://%s:%s", tgitea.HTTPListenAddress, tgitea.HTTPPort)
	giteaClient := gitea.NewClient(giteaAPIURL, "")

	giteaClient.SetBasicAuth(giteaUser01, "password")
	giteaToken, err := giteaClient.CreateAccessToken(gitea.CreateAccessTokenOption{Name: "token01"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	t.Logf("created gitea user token: %s", giteaToken.Token)

	gwClient := gwclient.NewClient(c.Gateway.APIExposedURL, "admintoken")
	user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	t.Logf("created agola user: %s", user.UserName)

	token := createAgolaUserToken(ctx, t, c)

	rs, _, err := gwClient.CreateRemoteSource(ctx, &gwapitypes.CreateRemoteSourceRequest{
		Name:                "gitea",
		APIURL:              giteaAPIURL,
		Type:                "gitea",
		AuthType:            "password",
		SkipSSHHostKeyCheck: true,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	t.Logf("created agola remote source: %s", rs.Name)

	// From now use the user token
	gwClient = gwclient.NewClient(c.Gateway.APIExposedURL, token)

	la, _, err := gwClient.CreateUserLA(ctx, agolaUser01, &gwapitypes.CreateUserLARequest{
		RemoteSourceName:          "gitea",
		RemoteSourceLoginName:     giteaUser01,
		RemoteSourceLoginPassword: "password",
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	t.Logf("created user linked account: %s", util.Dump(la))

	return giteaToken.Token, token
}

func TestCreateProject(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tetcd, tgitea, c := setup(ctx, t, dir)
	defer shutdownGitea(tgitea)
	defer shutdownEtcd(tetcd)

	giteaAPIURL := fmt.Sprintf("http://%s:%s", tgitea.HTTPListenAddress, tgitea.HTTPPort)

	giteaToken, token := createLinkedAccount(ctx, t, tgitea, c)

	giteaClient := gitea.NewClient(giteaAPIURL, giteaToken)
	gwClient := gwclient.NewClient(c.Gateway.APIExposedURL, token)

	createProject(ctx, t, giteaClient, gwClient)
}

func TestUpdateProject(t *testing.T) {

	tests := []struct {
		name               string
		passVarsToForkedPR bool
		expected_pre       bool
		expected_post      bool
	}{
		{
			name:               "test project update with pass-vars-to-forked-pr true",
			passVarsToForkedPR: true,
			expected_pre:       false,
			expected_post:      true,
		},
		{
			name:               "test project update with pass-vars-to-forked-pr false",
			passVarsToForkedPR: false,
			expected_pre:       false,
			expected_post:      false,
		},
	}

	for _, tt := range tests {
		dir, err := ioutil.TempDir("", "agola")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		defer os.RemoveAll(dir)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		tetcd, tgitea, c := setup(ctx, t, dir)
		defer shutdownGitea(tgitea)
		defer shutdownEtcd(tetcd)

		giteaAPIURL := fmt.Sprintf("http://%s:%s", tgitea.HTTPListenAddress, tgitea.HTTPPort)

		giteaToken, token := createLinkedAccount(ctx, t, tgitea, c)

		giteaClient := gitea.NewClient(giteaAPIURL, giteaToken)
		gwClient := gwclient.NewClient(c.Gateway.APIExposedURL, token)

		_, project := createProject(ctx, t, giteaClient, gwClient)
		if project.PassVarsToForkedPR != tt.expected_pre {
			t.Fatalf("expected PassVarsToForkedPR %v, got %v (pre-update)", tt.expected_pre, project.PassVarsToForkedPR)
		}
		project = updateProject(ctx, t, giteaClient, gwClient, project.ID, tt.passVarsToForkedPR)
		if project.PassVarsToForkedPR != tt.expected_post {
			t.Fatalf("expected PassVarsToForkedPR %v, got %v (port-update)", tt.expected_post, project.PassVarsToForkedPR)
		}
	}
}

func createProject(ctx context.Context, t *testing.T, giteaClient *gitea.Client, gwClient *gwclient.Client) (*gitea.Repository, *gwapitypes.ProjectResponse) {
	giteaRepo, err := giteaClient.CreateRepo(gitea.CreateRepoOption{
		Name:    "repo01",
		Private: false,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	t.Logf("created gitea repo: %s", giteaRepo.Name)

	project, _, err := gwClient.CreateProject(ctx, &gwapitypes.CreateProjectRequest{
		Name:             "project01",
		ParentRef:        path.Join("user", agolaUser01),
		RemoteSourceName: "gitea",
		RepoPath:         path.Join(giteaUser01, "repo01"),
		Visibility:       gwapitypes.VisibilityPublic,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	return giteaRepo, project
}

func updateProject(ctx context.Context, t *testing.T, giteaClient *gitea.Client, gwClient *gwclient.Client, projectRef string, passVarsToForkedPR bool) *gwapitypes.ProjectResponse {
	project, _, err := gwClient.UpdateProject(ctx, projectRef, &gwapitypes.UpdateProjectRequest{
		PassVarsToForkedPR: util.BoolP(passVarsToForkedPR),
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	return project
}

func push(t *testing.T, config, cloneURL, remoteToken, message string, pushNewBranch bool) {
	gitfs := memfs.New()
	f, err := gitfs.Create(".agola/config.jsonnet")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if _, err = f.Write([]byte(config)); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	r, err := git.Init(memory.NewStorage(), gitfs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if _, err := r.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{cloneURL},
	}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	wt, err := r.Worktree()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if _, err := wt.Add(".agola/config.jsonnet"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_, err = wt.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  "user01",
			Email: "user01@example.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	t.Logf("sshurl: %s", cloneURL)
	if err := r.Push(&git.PushOptions{
		RemoteName: "origin",
		Auth: &http.BasicAuth{
			Username: giteaUser01,
			Password: remoteToken,
		},
	}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if pushNewBranch {
		// change worktree and push to a new branch
		headRef, err := r.Head()
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		ref := plumbing.NewHashReference("refs/heads/new-branch", headRef.Hash())
		err = r.Storer.SetReference(ref)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		f, err = gitfs.Create("file1")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if _, err = f.Write([]byte("my file content")); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if _, err := wt.Add("file1"); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		_, err = wt.Commit("add file1", &git.CommitOptions{
			Author: &object.Signature{
				Name:  "user01",
				Email: "user01@example.com",
				When:  time.Now(),
			},
		})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		if err := r.Push(&git.PushOptions{
			RemoteName: "origin",
			RefSpecs: []gitconfig.RefSpec{
				gitconfig.RefSpec("refs/heads/new-branch:refs/heads/new-branch"),
			},
			Auth: &http.BasicAuth{
				Username: giteaUser01,
				Password: remoteToken,
			},
		}); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}
}

func TestPush(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		num         int
		annotations map[string]string
		message     string
	}{
		{
			name: "test push",
			config: `
			{
			  runs: [
			    {
			      name: 'run01',
			      tasks: [
			        {
			          name: 'task01',
			          runtime: {
			            containers: [
			              {
			                image: 'alpine/git',
			              },
			            ],
			          },
			          steps: [
			            { type: 'clone' },
			            { type: 'run', command: 'env' },
			          ],
			        },
			      ],
			    },
			  ],
			}
			`,
			num: 1,
			annotations: map[string]string{
				"branch":   "master",
				"ref":      "refs/heads/master",
				"ref_type": "branch",
			},
			message: "commit",
		},
		{
			name: "test push with unmatched branch",
			config: `
			{
			  runs: [
			    {
			      name: 'run01',
			      tasks: [
			        {
			          name: 'task01',
			          runtime: {
			            containers: [
			              {
			                image: 'alpine/git',
			              },
			            ],
			          },
			          steps: [
			            { type: 'clone' },
			            { type: 'run', command: 'env' },
			          ],
			        },
			      ],
			      when: {
			        branch: 'notmaster',
			      },
			    },
			  ],
			}
			`,
			num:     0,
			message: "commit",
		},
		{
			name: "test push with [ci skip] in subject",
			config: `
                        {
                          runs: [
                            {
                              name: 'run01',
                              tasks: [
                                {
                                  name: 'task01',
                                  runtime: {
                                    containers: [
                                      {
                                        image: 'alpine/git',
                                      },
                                    ],
                                  },
                                  steps: [
                                    { type: 'clone' },
                                    { type: 'run', command: 'env' },
                                  ],
                                },
                              ],
                            },
                          ],
                        }
                        `,
			num:     0,
			message: "[ci skip] commit",
		},
		{
			name: "test push with [ci skip] in body",
			config: `
                        {
                          runs: [
                            {
                              name: 'run01',
                              tasks: [
                                {
                                  name: 'task01',
                                  runtime: {
                                    containers: [
                                      {
                                        image: 'alpine/git',
                                      },
                                    ],
                                  },
                                  steps: [
                                    { type: 'clone' },
                                    { type: 'run', command: 'env' },
                                  ],
                                },
                              ],
                            },
                          ],
                        }
                        `,
			num:     0,
			message: "commit\n\n[ci skip] body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			dir, err := ioutil.TempDir("", "agola")
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			defer os.RemoveAll(dir)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			tetcd, tgitea, c := setup(ctx, t, dir)
			defer shutdownGitea(tgitea)
			defer shutdownEtcd(tetcd)

			giteaAPIURL := fmt.Sprintf("http://%s:%s", tgitea.HTTPListenAddress, tgitea.HTTPPort)

			giteaToken, token := createLinkedAccount(ctx, t, tgitea, c)

			giteaClient := gitea.NewClient(giteaAPIURL, giteaToken)
			gwClient := gwclient.NewClient(c.Gateway.APIExposedURL, token)

			giteaRepo, project := createProject(ctx, t, giteaClient, gwClient)

			push(t, tt.config, giteaRepo.CloneURL, giteaToken, tt.message, false)

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetRuns(ctx, nil, nil, []string{path.Join("/project", project.ID)}, nil, "", 0, false)
				if err != nil {
					return false, nil
				}

				if len(runs) == 0 {
					return false, nil
				}
				run := runs[0]
				if run.Phase != rstypes.RunPhaseFinished {
					return false, nil
				}

				return true, nil
			})

			runs, _, err := gwClient.GetRuns(ctx, nil, nil, []string{path.Join("/project", project.ID)}, nil, "", 0, false)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			t.Logf("runs: %s", util.Dump(runs))

			if len(runs) != tt.num {
				t.Fatalf("expected %d run got: %d", tt.num, len(runs))
			}

			if len(runs) > 0 {
				run := runs[0]
				if run.Phase != rstypes.RunPhaseFinished {
					t.Fatalf("expected run phase %q, got %q", rstypes.RunPhaseFinished, run.Phase)
				}
				if run.Result != rstypes.RunResultSuccess {
					t.Fatalf("expected run result %q, got %q", rstypes.RunResultSuccess, run.Result)
				}
				for k, v := range tt.annotations {
					if run.Annotations[k] != v {
						t.Fatalf("expected run annotation %q value %q, got %q", k, v, run.Annotations[k])
					}
				}
			}

		})
	}
}

func directRun(t *testing.T, dir, config string, configFormat ConfigFormat, gatewayURL, token string, args ...string) {
	agolaBinDir := os.Getenv("AGOLA_BIN_DIR")
	if agolaBinDir == "" {
		t.Fatalf("env var AGOLA_BIN_DIR is undefined")
	}
	agolaBinDir, err := filepath.Abs(agolaBinDir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	repoDir, err := ioutil.TempDir(dir, "repo")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	gitfs := osfs.New(repoDir)
	dot, _ := gitfs.Chroot(".git")

	var configPath string
	switch configFormat {
	case ConfigFormatJsonnet:
		configPath = ".agola/config.jsonnet"
	case ConfigFormatStarlark:
		configPath = ".agola/config.star"
	}

	f, err := gitfs.Create(configPath)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if _, err = f.Write([]byte(config)); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	_, err = git.Init(filesystem.NewStorage(dot, cache.NewObjectLRUDefault()), gitfs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	args = append([]string{"--gateway-url", gatewayURL, "--token", token, "directrun", "start", "--untracked", "false"}, args...)
	cmd := exec.Command(filepath.Join(agolaBinDir, "agola"), args...)
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unexpected err: %v, out: %s", err, out)
	}
	t.Logf("directrun start out: %s", out)
}

func TestDirectRun(t *testing.T) {
	config := `
      {
        runs: [
          {
            name: 'run01',
            tasks: [
              {
                name: 'task01',
                runtime: {
                  containers: [
                    {
                      image: 'alpine/git',
                    },
                  ],
                },
                steps: [
                  { type: 'clone' },
                  { type: 'run', command: 'env' },
                ],
              },
            ],
          },
        ],
      }
    `

	tests := []struct {
		name        string
		args        []string
		annotations map[string]string
	}{
		{
			name: "test direct run",
			annotations: map[string]string{
				"branch":   "master",
				"ref":      "refs/heads/master",
				"ref_type": "branch",
			},
		},
		{
			name: "test direct run with destination branch",
			args: []string{"--branch", "develop"},
			annotations: map[string]string{
				"branch":   "develop",
				"ref":      "refs/heads/develop",
				"ref_type": "branch",
			},
		},
		{
			name: "test direct run with destination tag",
			args: []string{"--tag", "v0.1.0"},
			annotations: map[string]string{
				"tag":      "v0.1.0",
				"ref":      "refs/tags/v0.1.0",
				"ref_type": "tag",
			},
		},
		{
			name: "test direct run with destination ref as a pr",
			args: []string{"--ref", "refs/pull/1/head"},
			annotations: map[string]string{
				"pull_request_id": "1",
				"ref":             "refs/pull/1/head",
				"ref_type":        "pull_request",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := ioutil.TempDir("", "agola")
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			defer os.RemoveAll(dir)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			tetcd, tgitea, c := setup(ctx, t, dir)
			defer shutdownGitea(tgitea)
			defer shutdownEtcd(tetcd)

			gwClient := gwclient.NewClient(c.Gateway.APIExposedURL, "admintoken")
			user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			t.Logf("created agola user: %s", user.UserName)

			token := createAgolaUserToken(ctx, t, c)

			// From now use the user token
			gwClient = gwclient.NewClient(c.Gateway.APIExposedURL, token)

			directRun(t, dir, config, ConfigFormatJsonnet, c.Gateway.APIExposedURL, token, tt.args...)

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetRuns(ctx, nil, nil, []string{path.Join("/user", user.ID)}, nil, "", 0, false)
				if err != nil {
					return false, nil
				}

				if len(runs) != 1 {
					return false, nil
				}

				run := runs[0]
				if run.Phase != rstypes.RunPhaseFinished {
					return false, nil
				}

				return true, nil
			})

			runs, _, err := gwClient.GetRuns(ctx, nil, nil, []string{path.Join("/user", user.ID)}, nil, "", 0, false)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			t.Logf("runs: %s", util.Dump(runs))

			if len(runs) != 1 {
				t.Fatalf("expected 1 run got: %d", len(runs))
			}

			run := runs[0]
			if run.Phase != rstypes.RunPhaseFinished {
				t.Fatalf("expected run phase %q, got %q", rstypes.RunPhaseFinished, run.Phase)
			}
			if run.Result != rstypes.RunResultSuccess {
				t.Fatalf("expected run result %q, got %q", rstypes.RunResultSuccess, run.Result)
			}
			for k, v := range tt.annotations {
				if run.Annotations[k] != v {
					t.Fatalf("expected run annotation %q value %q, got %q", k, v, run.Annotations[k])
				}
			}
		})
	}
}

func TestDirectRunVariables(t *testing.T) {
	config := `
      {
        runs: [
          {
            name: 'run01',
            tasks: [
              {
                name: 'task01',
                runtime: {
                  containers: [
                    {
                      image: 'alpine/git',
                    },
                  ],
                },
                environment: {
                  ENV01: { from_variable: 'variable01' },
                  ENV02: { from_variable: 'variable02' },
                },
                steps: [
                  { type: 'clone' },
                  { type: 'run', command: 'env' },
                ],
              },
            ],
          },
        ],
      }
	`

	varfile01 := `
      variable01: "variable value 01"
      variable02: variable value 02
`

	tests := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{
			name: "test direct run without variables",
			args: []string{},
			env: map[string]string{
				"ENV01": "",
				"ENV02": "",
			},
		},
		{
			name: "test direct run with two variables",
			args: []string{"--var", "variable01=VARIABLEVALUE01", "--var", "variable02=VARIABLEVALUE02"},
			env: map[string]string{
				"ENV01": "VARIABLEVALUE01",
				"ENV02": "VARIABLEVALUE02",
			},
		},
		{
			name: "test direct run with a var file",
			args: []string{"--var-file", "../varfile01.yml"},
			env: map[string]string{
				"ENV01": "variable value 01",
				"ENV02": "variable value 02",
			},
		},
		{
			name: "test direct run with a var file and a var that overrides",
			args: []string{"--var-file", "../varfile01.yml", "--var", "variable02=VARIABLEVALUE02"},
			env: map[string]string{
				"ENV01": "variable value 01",
				"ENV02": "VARIABLEVALUE02",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := ioutil.TempDir("", "agola")
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			defer os.RemoveAll(dir)

			if err := ioutil.WriteFile(filepath.Join(dir, "varfile01.yml"), []byte(varfile01), 0644); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			tetcd, tgitea, c := setup(ctx, t, dir)
			defer shutdownGitea(tgitea)
			defer shutdownEtcd(tetcd)

			gwClient := gwclient.NewClient(c.Gateway.APIExposedURL, "admintoken")
			user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			t.Logf("created agola user: %s", user.UserName)

			token := createAgolaUserToken(ctx, t, c)

			// From now use the user token
			gwClient = gwclient.NewClient(c.Gateway.APIExposedURL, token)

			directRun(t, dir, config, ConfigFormatJsonnet, c.Gateway.APIExposedURL, token, tt.args...)

			// TODO(sgotti) add an util to wait for a run phase
			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetRuns(ctx, nil, nil, []string{path.Join("/user", user.ID)}, nil, "", 0, false)
				if err != nil {
					return false, nil
				}

				if len(runs) != 1 {
					return false, nil
				}

				run := runs[0]
				if run.Phase != rstypes.RunPhaseFinished {
					return false, nil
				}

				return true, nil
			})

			runs, _, err := gwClient.GetRuns(ctx, nil, nil, []string{path.Join("/user", user.ID)}, nil, "", 0, false)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			t.Logf("runs: %s", util.Dump(runs))

			if len(runs) != 1 {
				t.Fatalf("expected 1 run got: %d", len(runs))
			}

			run, _, err := gwClient.GetRun(ctx, runs[0].ID)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if run.Phase != rstypes.RunPhaseFinished {
				t.Fatalf("expected run phase %q, got %q", rstypes.RunPhaseFinished, run.Phase)
			}
			if run.Result != rstypes.RunResultSuccess {
				t.Fatalf("expected run result %q, got %q", rstypes.RunResultSuccess, run.Result)
			}

			var task *gwapitypes.RunResponseTask
			for _, t := range run.Tasks {
				if t.Name == "task01" {
					task = t
					break
				}
			}

			resp, err := gwClient.GetLogs(ctx, run.ID, task.ID, false, 1, false)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			defer resp.Body.Close()

			logs, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			curEnv, err := testutil.ParseEnvs(bytes.NewReader(logs))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			for n, e := range tt.env {
				if ce, ok := curEnv[n]; !ok {
					t.Fatalf("missing env var %s", n)
				} else {
					if ce != e {
						t.Fatalf("different env var %s value, want: %q, got %q", n, e, ce)
					}
				}
			}
		})
	}
}

func TestDirectRunLogs(t *testing.T) {
	config := `
      {
        runs: [
          {
            name: 'run01',
            tasks: [
              {
                name: 'task01',
                runtime: {
                  containers: [
                    {
                      image: 'alpine/git',
                    },
                  ],
                },
                steps: [
                  { type: 'clone' },
                  { type: 'run', command: 'echo STEPLOG' },
                ],
              },
            ],
          },
        ],
      }
    `

	tests := []struct {
		name   string
		setup  bool
		step   int
		delete bool
		err    error
	}{
		{
			name: "test get log step 1",
			step: 1,
		},
		{
			name:  "test get log setup",
			setup: true,
		},
		{
			name: "test get log with unexisting step",
			step: 99,
			err:  errors.Errorf("log doesn't exist"),
		},
		{
			name:   "test delete log step 1",
			step:   1,
			delete: true,
		},
		{
			name:   "test delete log setup",
			setup:  true,
			delete: true,
		},
		{
			name:   "test delete log with unexisting step",
			step:   99,
			delete: true,
			err:    errors.Errorf("log doesn't exist"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := ioutil.TempDir("", "agola")
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			defer os.RemoveAll(dir)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			tetcd, tgitea, c := setup(ctx, t, dir)
			defer shutdownGitea(tgitea)
			defer shutdownEtcd(tetcd)

			gwClient := gwclient.NewClient(c.Gateway.APIExposedURL, "admintoken")
			user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			t.Logf("created agola user: %s", user.UserName)

			token := createAgolaUserToken(ctx, t, c)

			// From now use the user token
			gwClient = gwclient.NewClient(c.Gateway.APIExposedURL, token)

			directRun(t, dir, config, ConfigFormatJsonnet, c.Gateway.APIExposedURL, token)

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetRuns(ctx, nil, nil, []string{path.Join("/user", user.ID)}, nil, "", 0, false)
				if err != nil {
					return false, nil
				}

				if len(runs) != 1 {
					return false, nil
				}

				run := runs[0]
				if run.Phase != rstypes.RunPhaseFinished {
					return false, nil
				}

				return true, nil
			})

			runs, _, err := gwClient.GetRuns(ctx, nil, nil, []string{path.Join("/user", user.ID)}, nil, "", 0, false)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			t.Logf("runs: %s", util.Dump(runs))

			if len(runs) != 1 {
				t.Fatalf("expected 1 run got: %d", len(runs))
			}

			run, _, err := gwClient.GetRun(ctx, runs[0].ID)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			if run.Phase != rstypes.RunPhaseFinished {
				t.Fatalf("expected run phase %q, got %q", rstypes.RunPhaseFinished, run.Phase)
			}
			if run.Result != rstypes.RunResultSuccess {
				t.Fatalf("expected run result %q, got %q", rstypes.RunResultSuccess, run.Result)
			}

			var task *gwapitypes.RunResponseTask
			for _, t := range run.Tasks {
				if t.Name == "task01" {
					task = t
					break
				}
			}

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				t, _, err := gwClient.GetRunTask(ctx, runs[0].ID, task.ID)
				if err != nil {
					return false, nil
				}
				if tt.step >= len(t.Steps) {
					return true, nil
				}
				if !t.Steps[tt.step].LogArchived {
					return false, nil
				}
				return true, nil
			})

			if tt.delete {
				_, err = gwClient.DeleteLogs(ctx, run.ID, task.ID, tt.setup, tt.step)
			} else {
				_, err = gwClient.GetLogs(ctx, run.ID, task.ID, tt.setup, tt.step, false)
			}

			if err != nil {
				if tt.err == nil {
					t.Fatalf("got error: %v, expected no error", err)
				}
				if !strings.HasPrefix(err.Error(), tt.err.Error()) {
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

func TestPullRequest(t *testing.T) {
	config := `
       {
         runs: [
           {
             name: 'run01',
             tasks: [
               {
                 name: 'task01',
                 runtime: {
                   containers: [
                     {
                       image: 'alpine/git',
                     },
                   ],
                 },
                 environment: {
                   MYPASSWORD: { from_variable: 'mypassword' },
                 },
                 steps: [
                   { type: 'clone' },
                   { type: 'run', command: 'echo -n $MYPASSWORD' },
                 ],
               },
             ],
             when: {
               ref: '#refs/pull/\\d+/head#',
             },
           },
         ],
       }
    `

	tests := []struct {
		name               string
		passVarsToForkedPR bool
		prFromSameRepo     bool
		expected           string
	}{
		{
			name:               "test PR from same repowith PassVarsToForkedPR set to false",
			passVarsToForkedPR: false,
			prFromSameRepo:     true,
			expected:           "mysupersecretpassword",
		},
		{
			name:               "test PR from same repo with PassVarsToForkedPR set to true",
			passVarsToForkedPR: true,
			prFromSameRepo:     true,
			expected:           "mysupersecretpassword",
		},
		{
			name:               "test PR from forked repo with PassVarsToForkedPR set to false",
			passVarsToForkedPR: false,
			prFromSameRepo:     false,
			expected:           "",
		},
		{
			name:               "test PR from forked repo with PassVarsToForkedPR set to true",
			passVarsToForkedPR: true,
			prFromSameRepo:     false,
			expected:           "mysupersecretpassword",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			dir, err := ioutil.TempDir("", "agola")
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			defer os.RemoveAll(dir)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			tetcd, tgitea, c := setup(ctx, t, dir)
			defer shutdownGitea(tgitea)
			defer shutdownEtcd(tetcd)

			giteaAPIURL := fmt.Sprintf("http://%s:%s", tgitea.HTTPListenAddress, tgitea.HTTPPort)

			giteaToken, token := createLinkedAccount(ctx, t, tgitea, c)

			giteaClient := gitea.NewClient(giteaAPIURL, giteaToken)
			gwClient := gwclient.NewClient(c.Gateway.APIExposedURL, token)

			giteaRepo, project := createProject(ctx, t, giteaClient, gwClient)
			project = updateProject(ctx, t, giteaClient, gwClient, project.ID, tt.passVarsToForkedPR)

			//create project secret
			secretData := map[string]string{"mypassword": "mysupersecretpassword"}
			sreq := &gwapitypes.CreateSecretRequest{
				Name: "mysecret",
				Type: gwapitypes.SecretTypeInternal,
				Data: secretData,
			}

			secret, _, err := gwClient.CreateProjectSecret(context.TODO(), project.ID, sreq)
			if err != nil {
				t.Fatal("failed to create project secret: %w", err)
			}

			// create project variable
			rvalues := []gwapitypes.VariableValueRequest{}
			rvalues = append(rvalues, gwapitypes.VariableValueRequest{
				SecretName: secret.Name,
				SecretVar:  "mypassword",
			})

			vreq := &gwapitypes.CreateVariableRequest{
				Name:   "mypassword",
				Values: rvalues,
			}

			_, _, err = gwClient.CreateProjectVariable(context.TODO(), project.ID, vreq)
			if err != nil {
				t.Fatal("failed to create project variable: %w", err)
			}

			if tt.prFromSameRepo {
				// create PR from branch on same repo
				push(t, config, giteaRepo.CloneURL, giteaToken, "commit", true)

				prOpts := gitea.CreatePullRequestOption{
					Head:  "new-branch",
					Base:  "master",
					Title: "add file1 from new-branch on same repo",
				}
				_, err = giteaClient.CreatePullRequest(giteaUser01, "repo01", prOpts)
				if err != nil {
					t.Fatal("failed to create pull request: %w", err)
				}
			} else {
				// create PR from forked repo
				push(t, config, giteaRepo.CloneURL, giteaToken, "commit", false)

				userOpts := gitea.CreateUserOption{
					Username:           giteaUser02,
					Password:           "password",
					Email:              "user02@example.com",
					MustChangePassword: util.BoolP(false),
				}
				_, err := giteaClient.AdminCreateUser(userOpts)
				if err != nil {
					t.Fatal("failed to create user02: %w", err)
				}

				giteaClient.SetBasicAuth(giteaUser02, "password")
				giteaUser02Token, err := giteaClient.CreateAccessToken(gitea.CreateAccessTokenOption{Name: "token01"})
				if err != nil {
					t.Fatalf("failed to create token for user02: %v", err)
				}

				giteaUser02Client := gitea.NewClient(giteaAPIURL, giteaUser02Token.Token)
				giteaForkedRepo, err := giteaUser02Client.CreateFork(giteaUser01, "repo01", gitea.CreateForkOption{})
				if err != nil {
					t.Fatal("failed to fork repo01: %w", err)
				}

				gitfs := memfs.New()
				r, err := git.Clone(memory.NewStorage(), gitfs, &git.CloneOptions{
					Auth: &http.BasicAuth{
						Username: giteaUser02,
						Password: giteaUser02Token.Token,
					},
					URL: giteaForkedRepo.CloneURL,
				})
				if err != nil {
					t.Fatalf("failed to clone forked repo: %v", err)
				}

				wt, err := r.Worktree()
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				f, err := gitfs.Create("file2")
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if _, err = f.Write([]byte("file2 content")); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if _, err := wt.Add("file2"); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				_, err = wt.Commit("commit from user02", &git.CommitOptions{
					Author: &object.Signature{
						Name:  giteaUser02,
						Email: "user02@example.com",
						When:  time.Now(),
					},
				})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				if err := r.Push(&git.PushOptions{
					RemoteName: "origin",
					RefSpecs: []gitconfig.RefSpec{
						gitconfig.RefSpec("refs/heads/master:refs/heads/master"),
					},
					Auth: &http.BasicAuth{
						Username: giteaUser02,
						Password: giteaUser02Token.Token,
					},
				}); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				prOpts := gitea.CreatePullRequestOption{
					Head:  "user02:master",
					Base:  "master",
					Title: "add file1 from master on forked repo",
				}
				_, err = giteaUser02Client.CreatePullRequest(giteaUser01, "repo01", prOpts)
				if err != nil {
					t.Fatal("failed to create pull request: %w", err)
				}
			}
			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetRuns(ctx, nil, nil, []string{path.Join("/project", project.ID)}, nil, "", 0, false)
				if err != nil {
					return false, nil
				}

				if len(runs) == 0 {
					return false, nil
				}
				run := runs[0]
				if run.Phase != rstypes.RunPhaseFinished {
					return false, nil
				}

				return true, nil
			})

			runs, _, err := gwClient.GetRuns(ctx, nil, nil, []string{path.Join("/project", project.ID)}, nil, "", 0, false)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			t.Logf("runs: %s", util.Dump(runs))

			run, _, err := gwClient.GetRun(ctx, runs[0].ID)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			var task *gwapitypes.RunResponseTask
			for _, t := range run.Tasks {
				if t.Name == "task01" {
					task = t
					break
				}
			}

			if len(runs) > 0 {
				run := runs[0]
				if run.Phase != rstypes.RunPhaseFinished {
					t.Fatalf("expected run phase %q, got %q", rstypes.RunPhaseFinished, run.Phase)
				}
				if run.Result != rstypes.RunResultSuccess {
					t.Fatalf("expected run result %q, got %q", rstypes.RunResultSuccess, run.Result)
				}
				resp, err := gwClient.GetLogs(ctx, run.ID, task.ID, false, 1, false)
				if err != nil {
					t.Fatalf("failed to get log: %v", err)
				}
				defer resp.Body.Close()

				mypassword, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("failed to read log: %v", err)
				}
				if tt.expected != string(mypassword) {
					t.Fatalf("expected mypassword %q, got %q", tt.expected, string(mypassword))
				}
			}
		})
	}
}

func TestConfigContext(t *testing.T) {
	jsonnetConfig := `
function(ctx) {
  runs: [
    {
      name: 'run01',
      tasks: [
        {
          name: 'task01',
          runtime: {
            containers: [
              {
                image: 'alpine/git',
              },
            ],
          },
          environment: {
            REF_TYPE: ctx.ref_type,
            REF: ctx.ref,
            BRANCH: ctx.branch,
            TAG: ctx.tag,
            PULL_REQUEST_ID: ctx.pull_request_id,
            COMMIT_SHA: ctx.commit_sha,
          },
          steps: [
            { type: 'clone' },
            { type: 'run', command: 'env' },
          ],
        },
      ],
    },
  ],
}
`

	starlarkConfig := `
def main(ctx):
  return {
    "runs": [
    {
      "name": 'run01',
      "tasks": [
        {
          "name": 'task01',
          "runtime": {
            "containers": [
              {
                "image": 'alpine/git',
              }
            ]
          },
          "environment": {
            "REF_TYPE": ctx["ref_type"],
            "REF": ctx["ref"],
            "BRANCH": ctx["branch"],
            "TAG": ctx["tag"],
            "PULL_REQUEST_ID": ctx["pull_request_id"],
            "COMMIT_SHA": ctx["commit_sha"]
          },
          "steps": [
            { "type": 'clone' },
            { "type": 'run', "command": 'env' }
          ],
        },
      ],
    },
  ]
}
`

	tests := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{
			name: "test direct run branch",
			env: map[string]string{
				"REF_TYPE":        "branch",
				"REF":             "refs/heads/master",
				"BRANCH":          "master",
				"TAG":             "",
				"PULL_REQUEST_ID": "",
				"COMMIT_SHA":      "",
			},
		},
		{
			name: "test direct run tag",
			args: []string{"--tag", "v0.1.0"},
			env: map[string]string{
				"REF_TYPE":        "tag",
				"REF":             "refs/tags/v0.1.0",
				"BRANCH":          "",
				"TAG":             "v0.1.0",
				"PULL_REQUEST_ID": "",
				"COMMIT_SHA":      "",
			},
		},
		{
			name: "test direct run with pr",
			args: []string{"--ref", "refs/pull/1/head"},
			env: map[string]string{
				"REF_TYPE":        "pull_request",
				"REF":             "refs/pull/1/head",
				"BRANCH":          "",
				"TAG":             "",
				"PULL_REQUEST_ID": "1",
				"COMMIT_SHA":      "",
			},
		},
	}

	for _, configFormat := range []ConfigFormat{ConfigFormatJsonnet, ConfigFormatStarlark} {
		for _, tt := range tests {
			t.Run(fmt.Sprintf("%s with %s config", tt.name, configFormat), func(t *testing.T) {
				var config string
				switch configFormat {
				case ConfigFormatJsonnet:
					config = jsonnetConfig
				case ConfigFormatStarlark:
					config = starlarkConfig
				}

				dir, err := ioutil.TempDir("", "agola")
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				defer os.RemoveAll(dir)

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				tetcd, tgitea, c := setup(ctx, t, dir)
				defer shutdownGitea(tgitea)
				defer shutdownEtcd(tetcd)

				gwClient := gwclient.NewClient(c.Gateway.APIExposedURL, "admintoken")
				user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				t.Logf("created agola user: %s", user.UserName)

				token := createAgolaUserToken(ctx, t, c)

				// From now use the user token
				gwClient = gwclient.NewClient(c.Gateway.APIExposedURL, token)

				directRun(t, dir, config, configFormat, c.Gateway.APIExposedURL, token, tt.args...)

				// TODO(sgotti) add an util to wait for a run phase
				_ = testutil.Wait(30*time.Second, func() (bool, error) {
					runs, _, err := gwClient.GetRuns(ctx, nil, nil, []string{path.Join("/user", user.ID)}, nil, "", 0, false)
					if err != nil {
						return false, nil
					}

					if len(runs) != 1 {
						return false, nil
					}

					run := runs[0]
					if run.Phase != rstypes.RunPhaseFinished {
						return false, nil
					}

					return true, nil
				})

				runs, _, err := gwClient.GetRuns(ctx, nil, nil, []string{path.Join("/user", user.ID)}, nil, "", 0, false)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				t.Logf("runs: %s", util.Dump(runs))

				if len(runs) != 1 {
					t.Fatalf("expected 1 run got: %d", len(runs))
				}

				run, _, err := gwClient.GetRun(ctx, runs[0].ID)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if run.Phase != rstypes.RunPhaseFinished {
					t.Fatalf("expected run phase %q, got %q", rstypes.RunPhaseFinished, run.Phase)
				}
				if run.Result != rstypes.RunResultSuccess {
					t.Fatalf("expected run result %q, got %q", rstypes.RunResultSuccess, run.Result)
				}

				var task *gwapitypes.RunResponseTask
				for _, t := range run.Tasks {
					if t.Name == "task01" {
						task = t
						break
					}
				}

				resp, err := gwClient.GetLogs(ctx, run.ID, task.ID, false, 1, false)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				defer resp.Body.Close()

				logs, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				curEnv, err := testutil.ParseEnvs(bytes.NewReader(logs))
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				// update commit sha from annotations since it will change at every test
				tt.env["COMMIT_SHA"] = run.Annotations["commit_sha"]

				for n, e := range tt.env {
					if ce, ok := curEnv[n]; !ok {
						t.Fatalf("missing env var %s", n)
					} else {
						if ce != e {
							t.Fatalf("different env var %s value, want: %q, got %q", n, e, ce)
						}
					}
				}
			})
		}
	}
}
