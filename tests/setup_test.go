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
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"testing"
	"time"

	slog "agola.io/agola/internal/log"
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

	gtypes "code.gitea.io/gitea/modules/structs"
	"code.gitea.io/sdk/gitea"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	errors "golang.org/x/xerrors"
	"gopkg.in/src-d/go-billy.v4/memfs"
	"gopkg.in/src-d/go-git.v4"
	gitconfig "gopkg.in/src-d/go-git.v4/config"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
	"gopkg.in/src-d/go-git.v4/storage/memory"
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)

const (
	giteaUser01 = "user01"
	agolaUser01 = "user01"
)

func setupEtcd(t *testing.T, dir string) *testutil.TestEmbeddedEtcd {
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

func setupGitea(t *testing.T, dir string) *testutil.TestGitea {
	tgitea, err := testutil.NewTestGitea(t, logger, dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := tgitea.Start(); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	time.Sleep(5 * time.Second)

	cmd := exec.Command(tgitea.GiteaPath, "admin", "create-user", "--name", giteaUser01, "--email", giteaUser01+"@example.com", "--password", "password", "--admin", "--config", tgitea.ConfigPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("unexpected err: %v, out: %s", err, out)
	}

	return tgitea
}

func shutdownGitea(tgitea *testutil.TestGitea) {
	tgitea.Kill()
}

func startAgola(ctx context.Context, t *testing.T, dir string, c *config.Config) (<-chan error, error) {
	rs, err := rsscheduler.NewRunservice(ctx, &c.Runservice)
	if err != nil {
		return nil, errors.Errorf("failed to start run service scheduler: %w", err)
	}

	ex, err := executor.NewExecutor(&c.Executor)
	if err != nil {
		return nil, errors.Errorf("failed to start run service executor: %w", err)
	}

	cs, err := configstore.NewConfigstore(ctx, &c.Configstore)
	if err != nil {
		return nil, errors.Errorf("failed to start config store: %w", err)
	}

	sched, err := scheduler.NewScheduler(&c.Scheduler)
	if err != nil {
		return nil, errors.Errorf("failed to start scheduler: %w", err)
	}

	ns, err := notification.NewNotificationService(c)
	if err != nil {
		return nil, errors.Errorf("failed to start notification service: %w", err)
	}

	gw, err := gateway.NewGateway(c)
	if err != nil {
		return nil, errors.Errorf("failed to start gateway: %w", err)
	}

	gs, err := gitserver.NewGitserver(&c.Gitserver)
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
	toolboxPath := os.Getenv("AGOLA_TOOLBOX_PATH")
	if toolboxPath == "" {
		t.Fatalf("env var AGOLA_TOOLBOX_PATH is undefined")
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
			ToolboxPath:   toolboxPath,
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

	tgitea := setupGitea(t, dir)

	etcdDir := filepath.Join(dir, "etcd")
	tetcd := setupEtcd(t, etcdDir)

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

	gwURL := fmt.Sprintf("http://%s:%s", listenAddress, gwPort)
	csURL := fmt.Sprintf("http://%s:%s", listenAddress, csPort)
	rsURL := fmt.Sprintf("http://%s:%s", listenAddress, rsPort)
	gitServerURL := fmt.Sprintf("http://%s:%s", listenAddress, gitServerPort)

	c.Gateway.Web.ListenAddress = fmt.Sprintf("%s:%s", listenAddress, gwPort)
	c.Configstore.Web.ListenAddress = fmt.Sprintf("%s:%s", listenAddress, csPort)
	c.Runservice.Web.ListenAddress = fmt.Sprintf("%s:%s", listenAddress, rsPort)
	c.Executor.Web.ListenAddress = fmt.Sprintf("%s:%s", listenAddress, exPort)
	c.Gitserver.Web.ListenAddress = fmt.Sprintf("%s:%s", listenAddress, gitServerPort)

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

	errCh, err := startAgola(ctx, t, dir, c)
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

func createLinkedAccount(ctx context.Context, t *testing.T, tgitea *testutil.TestGitea, c *config.Config) (string, string) {
	giteaAPIURL := fmt.Sprintf("http://%s:%s", tgitea.ListenAddress, tgitea.HTTPPort)
	giteaClient := gitea.NewClient(giteaAPIURL, "")

	giteaToken, err := giteaClient.CreateAccessToken(giteaUser01, "password", gtypes.CreateAccessTokenOption{Name: "token01"})
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

	token, _, err := gwClient.CreateUserToken(ctx, agolaUser01, &gwapitypes.CreateUserTokenRequest{TokenName: "token01"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	t.Logf("created agola user token: %s", token.Token)

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
	gwClient = gwclient.NewClient(c.Gateway.APIExposedURL, token.Token)

	la, _, err := gwClient.CreateUserLA(ctx, agolaUser01, &gwapitypes.CreateUserLARequest{
		RemoteSourceName:          "gitea",
		RemoteSourceLoginName:     giteaUser01,
		RemoteSourceLoginPassword: "password",
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	t.Logf("created user linked account: %s", util.Dump(la))

	return giteaToken.Token, token.Token
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

	giteaAPIURL := fmt.Sprintf("http://%s:%s", tgitea.ListenAddress, tgitea.HTTPPort)

	giteaToken, token := createLinkedAccount(ctx, t, tgitea, c)

	giteaClient := gitea.NewClient(giteaAPIURL, giteaToken)
	gwClient := gwclient.NewClient(c.Gateway.APIExposedURL, token)

	createProject(ctx, t, giteaClient, gwClient)
}

func createProject(ctx context.Context, t *testing.T, giteaClient *gitea.Client, gwClient *gwclient.Client) (*gtypes.Repository, *gwapitypes.ProjectResponse) {
	giteaRepo, err := giteaClient.CreateRepo(gtypes.CreateRepoOption{
		Name: "repo01",
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

func TestRun(t *testing.T) {
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

	giteaAPIURL := fmt.Sprintf("http://%s:%s", tgitea.ListenAddress, tgitea.HTTPPort)

	giteaToken, token := createLinkedAccount(ctx, t, tgitea, c)

	giteaClient := gitea.NewClient(giteaAPIURL, giteaToken)
	gwClient := gwclient.NewClient(c.Gateway.APIExposedURL, token)

	giteaRepo, project := createProject(ctx, t, giteaClient, gwClient)

	gitfs := memfs.New()
	f, err := gitfs.Create(".agola/config.jsonnet")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_, err = f.Write([]byte(
		`{
  runs: [
    {
      name: 'run01',
      tasks: [
        {
          name: 'task01',
          runtime: {
            containers: [
              {
                image: 'busybox',
              },
            ],
          },
          steps: [
            { type: 'run', command: 'env' },
          ],
        },
      ],
    },
  ],
}
`))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	r, err := git.Init(memory.NewStorage(), gitfs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if _, err := r.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{giteaRepo.CloneURL},
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
	_, err = wt.Commit("commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "user01",
			Email: "user01@example.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	t.Logf("sshurl: %s", giteaRepo.CloneURL)
	if err := r.Push(&git.PushOptions{
		RemoteName: "origin",
		Auth: &http.BasicAuth{
			Username: giteaUser01,
			Password: giteaToken,
		},
	}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// TODO(sgotti) add an util to wait for a run phase
	time.Sleep(10 * time.Second)

	runs, _, err := gwClient.GetRuns(ctx, nil, nil, []string{path.Join("/project", project.ID)}, nil, "", 0, false)
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
}
