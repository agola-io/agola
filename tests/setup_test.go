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
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"code.gitea.io/sdk/gitea"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"
	"gotest.tools/assert"

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
)

const (
	giteaUser01         = "user01"
	giteaUser01Password = "user01password"
	giteaUser02         = "user02"
	giteaUser02Password = "user02password"

	agolaUser01 = "user01"
	agolaUser02 = "user02"
	agolaUser03 = "user03"

	agolaOrg01 = "org01"
	agolaOrg02 = "org02"
	agolaOrg03 = "org03"

	configstoreService = "configstore"
	runserviceService  = "runservice"

	webhookSecret = "secretkey"
)

type ConfigFormat string

const (
	// ConfigFormatJSON handles both json or yaml format (since json is a subset of yaml)
	ConfigFormatJSON     ConfigFormat = "json"
	ConfigFormatJsonnet  ConfigFormat = "jsonnet"
	ConfigFormatStarlark ConfigFormat = "starlark"
)

const (
	remoteErrorInternal     = "remote error internal"
	remoteErrorNotExist     = "remote error notexist"
	remoteErrorBadRequest   = "remote error badrequest"
	remoteErrorUnauthorized = "remote error unauthorized"
	remoteErrorForbidden    = "remote error forbidden"
)

const MaxLimit = 30

const EnvRunConfig = `
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
						{ type: 'run', command: 'env' },
					],
				},
			],
		},
	],
}
`

const FailingRunConfig = `
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
						{ type: 'run', command: 'false' },
					],
				},
			],
		},
	],
}
`

func setupGitea(t *testing.T, dir, dockerBridgeAddress string) *testutil.TestGitea {
	tgitea, err := testutil.NewTestGitea(t, dir, dockerBridgeAddress)
	testutil.NilError(t, err)
	err = tgitea.Start()
	testutil.NilError(t, err)

	giteaAPIURL := fmt.Sprintf("http://%s:%s", tgitea.HTTPListenAddress, tgitea.HTTPPort)

	// Wait for gitea api to be ready
	err = testutil.Wait(60*time.Second, func() (bool, error) {
		if _, err := http.Get(giteaAPIURL); err != nil {
			return false, nil
		}
		return true, nil
	})
	testutil.NilError(t, err)

	err = testutil.Wait(30*time.Second, func() (bool, error) {
		cmd := exec.Command(tgitea.GiteaPath, "admin", "user", "create", "--name", giteaUser01, "--email", giteaUser01+"@example.com", "--password", giteaUser01Password, "--admin", "--config", tgitea.ConfigPath)
		// just retry until no error
		if err := cmd.Run(); err != nil {
			return false, nil
		}
		return true, nil
	})
	testutil.NilError(t, err)

	giteaClient, err := gitea.NewClient(giteaAPIURL)
	testutil.NilError(t, err)

	// Wait for gitea api to be ready using gitea client
	err = testutil.Wait(30*time.Second, func() (bool, error) {
		giteaClient.SetBasicAuth(giteaUser01, giteaUser01Password)
		if _, _, err := giteaClient.ListAccessTokens(gitea.ListAccessTokensOptions{}); err != nil {
			return false, nil
		}
		return true, nil
	})
	testutil.NilError(t, err)

	return tgitea
}

type testAgola struct {
	wg *sync.WaitGroup

	errCh <-chan error

	cancel context.CancelFunc
}

func startAgola(pctx context.Context, t *testing.T, log zerolog.Logger, dir string, c *config.Config) (*testAgola, error) {
	ctx, cancel := context.WithCancel(pctx)
	wg := &sync.WaitGroup{}

	rs, err := rsscheduler.NewRunservice(ctx, log, &c.Runservice)
	if err != nil {
		cancel()
		return nil, errors.Wrapf(err, "failed to start run service scheduler")
	}

	ex, err := executor.NewExecutor(ctx, log, &c.Executor)
	if err != nil {
		cancel()
		return nil, errors.Wrapf(err, "failed to start run service executor")
	}

	cs, err := configstore.NewConfigstore(ctx, log, &c.Configstore)
	if err != nil {
		cancel()
		return nil, errors.Wrapf(err, "failed to start config store")
	}

	sched, err := scheduler.NewScheduler(ctx, log, &c.Scheduler)
	if err != nil {
		cancel()
		return nil, errors.Wrapf(err, "failed to start scheduler")
	}

	ns, err := notification.NewNotificationService(ctx, log, c)
	if err != nil {
		cancel()
		return nil, errors.Wrapf(err, "failed to start notification service")
	}

	gw, err := gateway.NewGateway(ctx, log, c)
	if err != nil {
		cancel()
		return nil, errors.Wrapf(err, "failed to start gateway")
	}

	gs, err := gitserver.NewGitserver(ctx, log, &c.Gitserver)
	if err != nil {
		cancel()
		return nil, errors.Wrapf(err, "failed to start git server")
	}

	wg.Add(7)
	errCh := make(chan error, 7)

	go func() { errCh <- rs.Run(ctx); wg.Done() }()
	go func() { errCh <- ex.Run(ctx); wg.Done() }()
	go func() { errCh <- cs.Run(ctx); wg.Done() }()
	go func() { errCh <- sched.Run(ctx); wg.Done() }()
	go func() { errCh <- ns.Run(ctx); wg.Done() }()
	go func() { errCh <- gw.Run(ctx); wg.Done() }()
	go func() { errCh <- gs.Run(ctx); wg.Done() }()

	// TODO(sgotti) find a better way to test that all is ready instead of sleeping
	time.Sleep(5 * time.Second)

	return &testAgola{
		wg:     wg,
		errCh:  errCh,
		cancel: cancel,
	}, nil
}

func (ta *testAgola) stop() {
	ta.cancel()
	ta.wg.Wait()
}

type setupContext struct {
	ctx context.Context
	t   *testing.T
	dir string
	log zerolog.Logger

	config                   *config.Config
	withGitea                bool
	withInternalServicesAuth bool

	agola *testAgola
	gitea *testutil.TestGitea

	mu sync.Mutex
}

type setupOption func(*setupContext)

func withGitea(gitea bool) func(*setupContext) {
	return func(s *setupContext) {
		s.withGitea = gitea
	}
}

func withOrganizationMemberAddingMode(organizationMemberAddingMode config.OrganizationMemberAddingMode) func(*setupContext) {
	return func(s *setupContext) {
		s.config.Gateway.OrganizationMemberAddingMode = organizationMemberAddingMode
	}
}

func withWebhooks(webhookURL string, webhookSecret string) func(*setupContext) {
	return func(s *setupContext) {
		s.config.Notification.WebhookURL = webhookURL
		s.config.Notification.WebhookSecret = webhookSecret
	}
}

func withInternalServicesAuth(enabled bool) func(*setupContext) {
	return func(s *setupContext) {
		s.withInternalServicesAuth = enabled
	}
}

func setup(ctx context.Context, t *testing.T, dir string, opts ...setupOption) *setupContext {
	log := testutil.NewLogger(t)

	dockerBridgeAddress := os.Getenv("DOCKER_BRIDGE_ADDRESS")
	if dockerBridgeAddress == "" {
		dockerBridgeAddress = "172.17.0.1"
	}
	agolaBinDir := os.Getenv("AGOLA_BIN_DIR")
	assert.Assert(t, agolaBinDir != "", "env var AGOLA_BIN_DIR is undefined")

	dbType := testutil.DBType(t)
	_, _, rsDBConnString := testutil.CreateDB(t, log, ctx, dir)
	_, _, csDBConnString := testutil.CreateDB(t, log, ctx, dir)
	_, _, notificationDBConnString := testutil.CreateDB(t, log, ctx, dir)

	sc := &setupContext{ctx: ctx, t: t, dir: dir, log: log}

	// enable internal services auth by default
	sc.withInternalServicesAuth = true

	sc.config = &config.Config{
		ID: "agola",
		Gateway: config.Gateway{
			Debug:           false,
			APIExposedURL:   "",
			WebExposedURL:   "",
			RunserviceURL:   "",
			ConfigstoreURL:  "",
			GitserverURL:    "",
			NotificationURL: "",
			Web: config.Web{
				ListenAddress: "",
				TLS:           false,
			},
			TokenSigning: config.TokenSigning{
				Duration: 12 * time.Hour,
				Method:   "hmac",
				Key:      "supersecretsigningkey",
			},
			CookieSigning: config.CookieSigning{
				Duration: 12 * time.Hour,
				Key:      "supersecretsigningkey",
			},
			AdminToken:                   "admintoken",
			OrganizationMemberAddingMode: config.OrganizationMemberAddingModeDirect,
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
			DB: config.DB{
				Type:       dbType,
				ConnString: notificationDBConnString,
			},
			Web: config.Web{
				ListenAddress: ":4004",
				TLS:           false,
			},
			RunWebhookExpireInterval:   7 * 24 * time.Hour,
			CommitStatusExpireInterval: 7 * 24 * time.Hour,
		},
		Runservice: config.Runservice{
			Debug:   false,
			DataDir: filepath.Join(dir, "runservice"),
			DB: config.DB{
				Type:       dbType,
				ConnString: rsDBConnString,
			},
			Web: config.Web{
				ListenAddress: ":4000",
				TLS:           false,
			},
			ObjectStorage: config.ObjectStorage{
				Type: "posix",
				Path: filepath.Join(dir, "runservice", "ost"),
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
			InitImage: config.InitImage{
				Image: "busybox:stable",
			},
		},
		Configstore: config.Configstore{
			Debug:   false,
			DataDir: filepath.Join(dir, "configstore"),
			DB: config.DB{
				Type:       dbType,
				ConnString: csDBConnString,
			},
			Web: config.Web{
				ListenAddress: ":4002",
				TLS:           false,
			},
			ObjectStorage: config.ObjectStorage{
				Type: "posix",
				Path: filepath.Join(dir, "configstore", "ost"),
			},
		},
		Gitserver: config.Gitserver{
			Debug:   false,
			DataDir: filepath.Join(dir, "gitserver"),
			Web: config.Web{
				ListenAddress: ":4003",
				TLS:           false,
			},
			RepositoryCleanupInterval: 24 * time.Hour,
		},
	}

	for _, o := range opts {
		o(sc)
	}

	if sc.withGitea {
		sc.gitea = setupGitea(t, dir, dockerBridgeAddress)
	}

	if sc.withInternalServicesAuth {
		runserviceAPIToken := "runserviceapitoken"
		executorAPIToken := "executorapitoken"
		configstoreAPIToken := "configstoreapitoken"
		gitserverAPIToken := "gitserverapitoken"
		notificationAPIToken := "notificationserverapitoken"

		sc.config.Gateway.RunserviceAPIToken = runserviceAPIToken
		sc.config.Gateway.ConfigstoreAPIToken = configstoreAPIToken
		sc.config.Gateway.GitserverAPIToken = gitserverAPIToken
		sc.config.Gateway.NotificationAPIToken = notificationAPIToken

		sc.config.Scheduler.RunserviceAPIToken = runserviceAPIToken

		sc.config.Notification.RunserviceAPIToken = runserviceAPIToken
		sc.config.Notification.ConfigstoreAPIToken = configstoreAPIToken

		sc.config.Runservice.APIToken = runserviceAPIToken
		sc.config.Runservice.ExecutorAPIToken = executorAPIToken

		sc.config.Executor.APIToken = executorAPIToken
		sc.config.Executor.RunserviceAPIToken = runserviceAPIToken

		sc.config.Configstore.APIToken = configstoreAPIToken

		sc.config.Gitserver.APIToken = gitserverAPIToken
	}

	gwPort, err := testutil.GetFreePort(dockerBridgeAddress, true, false)
	testutil.NilError(t, err)

	csPort, err := testutil.GetFreePort(dockerBridgeAddress, true, false)
	testutil.NilError(t, err)

	rsPort, err := testutil.GetFreePort(dockerBridgeAddress, true, false)
	testutil.NilError(t, err)

	exPort, err := testutil.GetFreePort(dockerBridgeAddress, true, false)
	testutil.NilError(t, err)

	nsPort, err := testutil.GetFreePort(dockerBridgeAddress, true, false)
	testutil.NilError(t, err)

	gitServerPort, err := testutil.GetFreePort(dockerBridgeAddress, true, false)
	testutil.NilError(t, err)

	gwURL := fmt.Sprintf("http://%s:%s", dockerBridgeAddress, gwPort)
	csURL := fmt.Sprintf("http://%s:%s", dockerBridgeAddress, csPort)
	rsURL := fmt.Sprintf("http://%s:%s", dockerBridgeAddress, rsPort)
	gitServerURL := fmt.Sprintf("http://%s:%s", dockerBridgeAddress, gitServerPort)
	nsURL := fmt.Sprintf("http://%s:%s", dockerBridgeAddress, nsPort)

	sc.config.Gateway.Web.ListenAddress = fmt.Sprintf("%s:%s", dockerBridgeAddress, gwPort)
	sc.config.Configstore.Web.ListenAddress = fmt.Sprintf("%s:%s", dockerBridgeAddress, csPort)
	sc.config.Runservice.Web.ListenAddress = fmt.Sprintf("%s:%s", dockerBridgeAddress, rsPort)
	sc.config.Executor.Web.ListenAddress = fmt.Sprintf("%s:%s", dockerBridgeAddress, exPort)
	sc.config.Notification.Web.ListenAddress = fmt.Sprintf("%s:%s", dockerBridgeAddress, nsPort)
	sc.config.Gitserver.Web.ListenAddress = fmt.Sprintf("%s:%s", dockerBridgeAddress, gitServerPort)
	sc.config.Notification.Web.ListenAddress = fmt.Sprintf("%s:%s", dockerBridgeAddress, nsPort)

	sc.config.Gateway.APIExposedURL = gwURL
	sc.config.Gateway.WebExposedURL = gwURL
	sc.config.Gateway.RunserviceURL = rsURL
	sc.config.Gateway.ConfigstoreURL = csURL
	sc.config.Gateway.GitserverURL = gitServerURL
	sc.config.Gateway.NotificationURL = nsURL

	sc.config.Scheduler.RunserviceURL = rsURL

	sc.config.Notification.WebExposedURL = gwURL
	sc.config.Notification.RunserviceURL = rsURL
	sc.config.Notification.ConfigstoreURL = csURL

	sc.config.Executor.RunserviceURL = rsURL
	err = sc.startAgola()
	testutil.NilError(t, err)

	go func() {
		<-ctx.Done()

		sc.stop()
	}()

	return sc
}

func (sc *setupContext) startAgola() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.agola != nil {
		return fmt.Errorf("agola already started")
	}
	tagola, err := startAgola(sc.ctx, sc.t, sc.log, sc.dir, sc.config)
	if err != nil {
		return err
	}
	go func() {
		err := <-tagola.errCh
		if err != nil {
			panic(errors.Wrap(err, "agola component returned error"))
		}
	}()

	sc.agola = tagola

	return nil
}

//nolint:unused
func (sc *setupContext) stopAgola() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.agola == nil {
		return fmt.Errorf("agola not started")
	}

	sc.agola.stop()
	sc.agola = nil

	return nil
}

//nolint:unused
func (sc *setupContext) restartAgola() error {
	if err := sc.stopAgola(); err != nil {
		return err
	}

	if err := sc.startAgola(); err != nil {
		return err
	}

	return nil
}

func (sc *setupContext) stop() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.gitea != nil {
		sc.gitea.Kill()
		sc.gitea = nil
	}

	if sc.agola != nil {
		sc.agola.stop()
		sc.agola = nil
	}
}

func createAgolaUserToken(ctx context.Context, t *testing.T, c *config.Config) string {
	gwClient := gwclient.NewClient(c.Gateway.APIExposedURL, "admintoken")
	token, _, err := gwClient.CreateUserToken(ctx, agolaUser01, &gwapitypes.CreateUserTokenRequest{TokenName: "token01"})
	testutil.NilError(t, err)

	t.Logf("created agola user token: %s", token.Token)

	return token.Token
}

func createLinkedAccount(ctx context.Context, t *testing.T, tgitea *testutil.TestGitea, c *config.Config) (string, string) {
	giteaAPIURL := fmt.Sprintf("http://%s:%s", tgitea.HTTPListenAddress, tgitea.HTTPPort)
	giteaClient, err := gitea.NewClient(giteaAPIURL)
	testutil.NilError(t, err)

	giteaClient.SetBasicAuth(giteaUser01, giteaUser01Password)
	giteaToken, _, err := giteaClient.CreateAccessToken(gitea.CreateAccessTokenOption{Name: "token01"})
	testutil.NilError(t, err)

	t.Logf("created gitea user token: %s", giteaToken.Token)

	adminGWClient := gwclient.NewClient(c.Gateway.APIExposedURL, "admintoken")
	user, _, err := adminGWClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
	testutil.NilError(t, err)

	t.Logf("created agola user: %s", user.UserName)

	token := createAgolaUserToken(ctx, t, c)

	rs, _, err := adminGWClient.CreateRemoteSource(ctx, &gwapitypes.CreateRemoteSourceRequest{
		Name:                "gitea",
		APIURL:              giteaAPIURL,
		Type:                "gitea",
		AuthType:            "password",
		SkipSSHHostKeyCheck: true,
	})
	testutil.NilError(t, err)

	t.Logf("created agola remote source: %s", rs.Name)

	tokenGWClient := gwclient.NewClient(c.Gateway.APIExposedURL, token)

	la, _, err := tokenGWClient.CreateUserLA(ctx, agolaUser01, &gwapitypes.CreateUserLARequest{
		RemoteSourceName:          "gitea",
		RemoteSourceLoginName:     giteaUser01,
		RemoteSourceLoginPassword: giteaUser01Password,
	})
	testutil.NilError(t, err)

	t.Logf("created user linked account: %s", util.Dump(la))

	return giteaToken.Token, token
}

type createProjectSetupOption func(*gwapitypes.CreateProjectRequest)

func withParentRef(parentRef string) func(*gwapitypes.CreateProjectRequest) {
	return func(p *gwapitypes.CreateProjectRequest) {
		p.ParentRef = parentRef
	}
}

func withMembersCanPerformRunActions(membersCanPerformRunActions bool) func(*gwapitypes.CreateProjectRequest) {
	return func(p *gwapitypes.CreateProjectRequest) {
		p.MembersCanPerformRunActions = membersCanPerformRunActions
	}
}

func withVisibility(visibility gwapitypes.Visibility) func(*gwapitypes.CreateProjectRequest) {
	return func(p *gwapitypes.CreateProjectRequest) {
		p.Visibility = visibility
	}
}

func createProject(ctx context.Context, t *testing.T, giteaClient *gitea.Client, gwClient *gwclient.Client, opts ...createProjectSetupOption) (*gitea.Repository, *gwapitypes.ProjectResponse) {
	giteaRepo, _, err := giteaClient.CreateRepo(gitea.CreateRepoOption{
		Name:    "repo01",
		Private: false,
	})
	testutil.NilError(t, err)

	t.Logf("created gitea repo: %s", giteaRepo.Name)

	// TODO currently RepoPath is always fixed and related to giteaUser01. Add withRepoPath function to make it configurable
	req := &gwapitypes.CreateProjectRequest{
		Name:             "project01",
		ParentRef:        path.Join("user", agolaUser01),
		RemoteSourceName: "gitea",
		RepoPath:         path.Join(giteaUser01, "repo01"),
		Visibility:       gwapitypes.VisibilityPublic,
	}

	for _, o := range opts {
		o(req)
	}

	project, _, err := gwClient.CreateProject(ctx, req)
	testutil.NilError(t, err)

	return giteaRepo, project
}

func push(t *testing.T, config, cloneURL, remoteToken, message string, pushNewBranch bool) {
	gitfs := memfs.New()
	f, err := gitfs.Create(".agola/config.jsonnet")
	testutil.NilError(t, err)
	_, err = f.Write([]byte(config))
	testutil.NilError(t, err)

	r, err := git.Init(memory.NewStorage(), gitfs)
	testutil.NilError(t, err)

	_, err = r.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{cloneURL},
	})
	testutil.NilError(t, err)

	wt, err := r.Worktree()
	testutil.NilError(t, err)
	_, err = wt.Add(".agola/config.jsonnet")
	testutil.NilError(t, err)

	_, err = wt.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  giteaUser01,
			Email: "user01@example.com",
			When:  time.Now(),
		},
	})
	testutil.NilError(t, err)

	t.Logf("sshurl: %s", cloneURL)
	err = r.Push(&git.PushOptions{
		RemoteName: "origin",
		Auth: &githttp.BasicAuth{
			Username: giteaUser01,
			Password: remoteToken,
		},
		Force: true,
	})
	testutil.NilError(t, err)

	if pushNewBranch {
		// change worktree and push to a new branch
		headRef, err := r.Head()
		testutil.NilError(t, err)

		ref := plumbing.NewHashReference("refs/heads/new-branch", headRef.Hash())
		err = r.Storer.SetReference(ref)
		testutil.NilError(t, err)

		f, err = gitfs.Create("file1")
		testutil.NilError(t, err)
		_, err = f.Write([]byte("my file content"))
		testutil.NilError(t, err)

		_, err = wt.Add("file1")
		testutil.NilError(t, err)

		_, err = wt.Commit("add file1", &git.CommitOptions{
			Author: &object.Signature{
				Name:  giteaUser01,
				Email: "user01@example.com",
				When:  time.Now(),
			},
		})
		testutil.NilError(t, err)

		err = r.Push(&git.PushOptions{
			RemoteName: "origin",
			RefSpecs: []gitconfig.RefSpec{
				gitconfig.RefSpec("refs/heads/new-branch:refs/heads/new-branch"),
			},
			Auth: &githttp.BasicAuth{
				Username: giteaUser01,
				Password: remoteToken,
			},
		})
		testutil.NilError(t, err)
	}
}

func directRun(t *testing.T, dir, config string, configFormat ConfigFormat, gatewayURL, token string, args ...string) {
	agolaBinDir := os.Getenv("AGOLA_BIN_DIR")
	assert.Assert(t, agolaBinDir != "", "env var AGOLA_BIN_DIR is undefined")

	agolaBinDir, err := filepath.Abs(agolaBinDir)
	testutil.NilError(t, err)

	repoDir, err := os.MkdirTemp(dir, "repo")
	testutil.NilError(t, err)

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
	testutil.NilError(t, err)
	_, err = f.Write([]byte(config))
	testutil.NilError(t, err)

	_, err = git.Init(filesystem.NewStorage(dot, cache.NewObjectLRUDefault()), gitfs)
	testutil.NilError(t, err)

	// override default gitconfig file to make it unique for test instance.
	// We have to override the HOME env var since GIT_CONFIG env is ignored.
	//
	// keep current env
	env := os.Environ()
	env = append(env, "HOME="+dir)

	// setup $HOME/.gitconfig
	gitConfigData := `
[user]
    name = TestGitea
    email = testgitea@example.com
`
	err = os.WriteFile(filepath.Join(dir, ".gitconfig"), []byte(gitConfigData), 0644)
	testutil.NilError(t, err)

	args = append([]string{"--gateway-url", gatewayURL, "--token", token, "directrun", "start", "--untracked", "false"}, args...)
	cmd := exec.Command(filepath.Join(agolaBinDir, "agola"), args...)
	cmd.Dir = repoDir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	testutil.NilError(t, err, "out: %s", out)

	t.Logf("directrun start out: %s", out)
}
