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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"code.gitea.io/sdk/gitea"
	"github.com/google/go-cmp/cmp"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"
	"gopkg.in/src-d/go-billy.v4/memfs"
	"gopkg.in/src-d/go-billy.v4/osfs"
	"gopkg.in/src-d/go-git.v4"
	gitconfig "gopkg.in/src-d/go-git.v4/config"
	"gopkg.in/src-d/go-git.v4/plumbing"
	"gopkg.in/src-d/go-git.v4/plumbing/cache"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	githttp "gopkg.in/src-d/go-git.v4/plumbing/transport/http"
	"gopkg.in/src-d/go-git.v4/storage/filesystem"
	"gopkg.in/src-d/go-git.v4/storage/memory"

	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/configstore"
	"agola.io/agola/internal/services/executor"
	"agola.io/agola/internal/services/gateway"
	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/services/gitserver"
	"agola.io/agola/internal/services/notification"
	rsscheduler "agola.io/agola/internal/services/runservice"
	"agola.io/agola/internal/services/scheduler"
	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
	csapitypes "agola.io/agola/services/configstore/api/types"
	cstypes "agola.io/agola/services/configstore/types"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"
	rstypes "agola.io/agola/services/runservice/types"
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
)

type ConfigFormat string

const (
	// ConfigFormatJSON handles both json or yaml format (since json is a subset of yaml)
	ConfigFormatJSON     ConfigFormat = "json"
	ConfigFormatJsonnet  ConfigFormat = "jsonnet"
	ConfigFormatStarlark ConfigFormat = "starlark"
)

const (
	GroupTypeProjects = "projects"
	GroupTypeUsers    = "users"
)

func setupGitea(t *testing.T, dir, dockerBridgeAddress string) *testutil.TestGitea {
	tgitea, err := testutil.NewTestGitea(t, dir, dockerBridgeAddress)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := tgitea.Start(); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	giteaAPIURL := fmt.Sprintf("http://%s:%s", tgitea.HTTPListenAddress, tgitea.HTTPPort)

	// Wait for gitea api to be ready
	err = testutil.Wait(60*time.Second, func() (bool, error) {
		if _, err := http.Get(giteaAPIURL); err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	err = testutil.Wait(30*time.Second, func() (bool, error) {
		cmd := exec.Command(tgitea.GiteaPath, "admin", "user", "create", "--name", giteaUser01, "--email", giteaUser01+"@example.com", "--password", giteaUser01Password, "--admin", "--config", tgitea.ConfigPath)
		// just retry until no error
		if err := cmd.Run(); err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	giteaClient, err := gitea.NewClient(giteaAPIURL)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// Wait for gitea api to be ready using gitea client
	err = testutil.Wait(30*time.Second, func() (bool, error) {
		giteaClient.SetBasicAuth(giteaUser01, giteaUser01Password)
		if _, _, err := giteaClient.ListAccessTokens(gitea.ListAccessTokensOptions{}); err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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
	if agolaBinDir == "" {
		t.Fatalf("env var AGOLA_BIN_DIR is undefined")
	}

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
			CookieSigning: config.CookieSigning{
				Duration: 12 * time.Hour,
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
			DB: config.DB{
				Type:       dbType,
				ConnString: notificationDBConnString,
			},
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

		sc.config.Gateway.RunserviceAPIToken = runserviceAPIToken
		sc.config.Gateway.ConfigstoreAPIToken = configstoreAPIToken
		sc.config.Gateway.GitserverAPIToken = gitserverAPIToken

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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	csPort, err := testutil.GetFreePort(dockerBridgeAddress, true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	rsPort, err := testutil.GetFreePort(dockerBridgeAddress, true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	exPort, err := testutil.GetFreePort(dockerBridgeAddress, true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	gitServerPort, err := testutil.GetFreePort(dockerBridgeAddress, true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	gwURL := fmt.Sprintf("http://%s:%s", dockerBridgeAddress, gwPort)
	csURL := fmt.Sprintf("http://%s:%s", dockerBridgeAddress, csPort)
	rsURL := fmt.Sprintf("http://%s:%s", dockerBridgeAddress, rsPort)
	gitServerURL := fmt.Sprintf("http://%s:%s", dockerBridgeAddress, gitServerPort)

	sc.config.Gateway.Web.ListenAddress = fmt.Sprintf("%s:%s", dockerBridgeAddress, gwPort)
	sc.config.Configstore.Web.ListenAddress = fmt.Sprintf("%s:%s", dockerBridgeAddress, csPort)
	sc.config.Runservice.Web.ListenAddress = fmt.Sprintf("%s:%s", dockerBridgeAddress, rsPort)
	sc.config.Executor.Web.ListenAddress = fmt.Sprintf("%s:%s", dockerBridgeAddress, exPort)
	sc.config.Gitserver.Web.ListenAddress = fmt.Sprintf("%s:%s", dockerBridgeAddress, gitServerPort)

	sc.config.Gateway.APIExposedURL = gwURL
	sc.config.Gateway.WebExposedURL = gwURL
	sc.config.Gateway.RunserviceURL = rsURL
	sc.config.Gateway.ConfigstoreURL = csURL
	sc.config.Gateway.GitserverURL = gitServerURL

	sc.config.Scheduler.RunserviceURL = rsURL

	sc.config.Notification.WebExposedURL = gwURL
	sc.config.Notification.RunserviceURL = rsURL
	sc.config.Notification.ConfigstoreURL = csURL

	sc.config.Executor.RunserviceURL = rsURL

	if err := sc.startAgola(); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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

func TestPasswordRegisterUser(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

	adminGWClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "admintoken")

	rs, _, err := adminGWClient.CreateRemoteSource(ctx, &gwapitypes.CreateRemoteSourceRequest{
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

	loginGWClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "")

	_, _, err = loginGWClient.RegisterUser(ctx, &gwapitypes.RegisterUserRequest{
		CreateUserRequest: gwapitypes.CreateUserRequest{
			UserName: agolaUser01,
		},
		CreateUserLARequest: gwapitypes.CreateUserLARequest{
			RemoteSourceName:          "gitea",
			RemoteSourceLoginName:     giteaUser01,
			RemoteSourceLoginPassword: giteaUser01Password,
		},
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	t.Logf("created agola user")

	loginUserResponse, _, err := loginGWClient.Login(ctx, &gwapitypes.LoginUserRequest{
		RemoteSourceName: "gitea",
		LoginName:        giteaUser01,
		LoginPassword:    giteaUser01Password,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// Register again. Should fail.
	_, _, err = loginGWClient.RegisterUser(ctx, &gwapitypes.RegisterUserRequest{
		CreateUserRequest: gwapitypes.CreateUserRequest{
			UserName: agolaUser01,
		},
		CreateUserLARequest: gwapitypes.CreateUserLARequest{
			RemoteSourceName:          "gitea",
			RemoteSourceLoginName:     giteaUser01,
			RemoteSourceLoginPassword: giteaUser01Password,
		},
	})
	expectedErr := "remote error badrequest"
	if err == nil {
		t.Fatalf("expected error %v, got nil err", expectedErr)
	}
	if err.Error() != expectedErr {
		t.Fatalf("expected err %v, got err: %v", expectedErr, err)
	}

	// Remove user
	if _, err := adminGWClient.DeleteUser(ctx, loginUserResponse.User.ID); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// Register again. Should work and recreate remote gitea user access token.
	_, _, err = loginGWClient.RegisterUser(ctx, &gwapitypes.RegisterUserRequest{
		CreateUserRequest: gwapitypes.CreateUserRequest{
			UserName: agolaUser01,
		},
		CreateUserLARequest: gwapitypes.CreateUserLARequest{
			RemoteSourceName:          "gitea",
			RemoteSourceLoginName:     giteaUser01,
			RemoteSourceLoginPassword: giteaUser01Password,
		},
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	token := createAgolaUserToken(ctx, t, sc.config)
	tokenGWClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

	// Do an agola call that will use the linkedAccount userAccessToken to call gitea api
	// should work
	if _, _, err := tokenGWClient.GetUserRemoteRepos(ctx, rs.ID); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestPasswordLogin(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

	adminGWClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "admintoken")

	rs, _, err := adminGWClient.CreateRemoteSource(ctx, &gwapitypes.CreateRemoteSourceRequest{
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

	loginGWClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "")

	_, _, err = loginGWClient.RegisterUser(ctx, &gwapitypes.RegisterUserRequest{
		CreateUserRequest: gwapitypes.CreateUserRequest{
			UserName: agolaUser01,
		},
		CreateUserLARequest: gwapitypes.CreateUserLARequest{
			RemoteSourceName:          "gitea",
			RemoteSourceLoginName:     giteaUser01,
			RemoteSourceLoginPassword: giteaUser01Password,
		},
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	t.Logf("created agola user")

	_, _, err = loginGWClient.Login(ctx, &gwapitypes.LoginUserRequest{
		RemoteSourceName: "gitea",
		LoginName:        giteaUser01,
		LoginPassword:    giteaUser01Password,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	token := createAgolaUserToken(ctx, t, sc.config)
	tokenGWClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

	// Test userAccessToken recreation on login
	giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetBasicAuth(giteaUser01, giteaUser01Password))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	giteaTokens, _, err := giteaClient.ListAccessTokens(gitea.ListAccessTokensOptions{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	for _, giteaToken := range giteaTokens {
		if _, err := giteaClient.DeleteAccessToken(giteaToken.Name); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}

	// Do an agola call that will use the linkedAccount userAccessToken to call gitea api
	// should fails since the registered token has been removed
	_, _, err = tokenGWClient.GetUserRemoteRepos(ctx, rs.ID)
	expectedErr := "remote error badrequest"
	if err == nil {
		t.Fatalf("expected error %v, got nil err", expectedErr)
	}
	if err.Error() != expectedErr {
		t.Fatalf("expected err %v, got err: %v", expectedErr, err)
	}

	// redo login. Should create a new gitea user access token
	_, _, err = loginGWClient.Login(ctx, &gwapitypes.LoginUserRequest{
		RemoteSourceName: "gitea",
		LoginName:        giteaUser01,
		LoginPassword:    giteaUser01Password,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// Do an agola call that will use the linkedAccount userAccessToken to call gitea api
	// should work
	if _, _, err := tokenGWClient.GetUserRemoteRepos(ctx, rs.ID); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestCookieAuth(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	_, _ = createLinkedAccount(ctx, t, sc.gitea, sc.config)

	gwCookieClient := newCookieClient(sc.config.Gateway.APIExposedURL)

	_, resp, err := gwCookieClient.Login(ctx, &gwapitypes.LoginUserRequest{
		RemoteSourceName: "gitea",
		LoginName:        giteaUser01,
		LoginPassword:    giteaUser01Password,
	}, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// Test auth passing recevied login response cookies
	authCookieName := common.AuthCookieName(false)
	secondaryAuthCookieName := common.SecondaryAuthCookieName()
	cookies := resp.Cookies()
	_, _, err = gwCookieClient.GetCurrentUser(ctx, cookies)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// Don't send  authcookie
	cookies = []*http.Cookie{}
	for _, c := range resp.Cookies() {
		if c.Name == authCookieName {
			continue
		}
		cookies = append(cookies, c)
	}

	_, _, err = gwCookieClient.GetCurrentUser(ctx, cookies)
	expectedErr := "remote error unauthorized"
	if err == nil {
		t.Fatalf("expected error %v, got nil err", expectedErr)
	}
	if err.Error() != expectedErr {
		t.Fatalf("expected err %v, got err: %v", expectedErr, err)
	}

	// Don't send secondary authcookie
	cookies = []*http.Cookie{}
	for _, c := range resp.Cookies() {
		if c.Name == secondaryAuthCookieName {
			continue
		}
		cookies = append(cookies, c)
	}

	_, _, err = gwCookieClient.GetCurrentUser(ctx, cookies)
	expectedErr = "remote error unauthorized"
	if err == nil {
		t.Fatalf("expected error %v, got nil err", expectedErr)
	}
	if err.Error() != expectedErr {
		t.Fatalf("expected err %v, got err: %v", expectedErr, err)
	}
}

func TestCSRF(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	_, _ = createLinkedAccount(ctx, t, sc.gitea, sc.config)

	gwCookieClient := newCookieClient(sc.config.Gateway.APIExposedURL)

	_, resp, err := gwCookieClient.Login(ctx, &gwapitypes.LoginUserRequest{
		RemoteSourceName: "gitea",
		LoginName:        giteaUser01,
		LoginPassword:    giteaUser01Password,
	}, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	loginCookies := resp.Cookies()

	// Do an initial request to fetch the csrf cookies and token
	_, resp, err = gwCookieClient.GetCurrentUser(ctx, loginCookies)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	t.Logf("resp.Header: %v", resp.Header)
	cookies := append(loginCookies, resp.Cookies()...)
	csrfToken := resp.Header.Get("X-Csrf-Token")
	header := http.Header{}
	header.Set("X-Csrf-Token", csrfToken)

	// Create an org. Should work
	if _, _, err := gwCookieClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic}, header, cookies); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// Don't send csrf token in request headers. Should return 403 (forbidden)
	_, _, err = gwCookieClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg02, Visibility: gwapitypes.VisibilityPublic}, http.Header{}, cookies)
	expectedErr := "unknown api error (status: 403)"
	if err == nil {
		t.Fatalf("expected error %v, got nil err", expectedErr)
	}
	if err.Error() != expectedErr {
		t.Fatalf("expected err %v, got err: %v", expectedErr, err)
	}

	csrfCookieName := common.CSRFCookieName(false)
	noCSRFCookies := []*http.Cookie{}
	for _, c := range cookies {
		if c.Name == csrfCookieName {
			continue
		}
		noCSRFCookies = append(noCSRFCookies, c)
	}

	// Don't send csrf cookie. Should return 403 (forbidden)
	_, _, err = gwCookieClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg02, Visibility: gwapitypes.VisibilityPublic}, header, noCSRFCookies)
	expectedErr = "unknown api error (status: 403)"
	if err == nil {
		t.Fatalf("expected error %v, got nil err", expectedErr)
	}
	if err.Error() != expectedErr {
		t.Fatalf("expected err %v, got err: %v", expectedErr, err)
	}

	// Send also an Authorization token that won't match to check that csrf check is done
	header.Set("Authorization", "Token unexistenttoken")

	_, _, err = gwCookieClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg02, Visibility: gwapitypes.VisibilityPublic}, header, noCSRFCookies)
	// Now we enforce and auth error if an Authorization token is provided and
	// the user for the token doesn't exist. In future we could add ways to
	// continue other auth checkers. The error should then be the commented one.
	// expectedErr = "unknown api error (status: 403)"
	expectedErr = "remote error unauthorized"
	if err == nil {
		t.Fatalf("expected error %v, got nil err", expectedErr)
	}
	if err.Error() != expectedErr {
		t.Fatalf("expected err %v, got err: %v", expectedErr, err)
	}
}

func TestCreateLinkedAccount(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	createLinkedAccount(ctx, t, sc.gitea, sc.config)
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
	giteaClient, err := gitea.NewClient(giteaAPIURL)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	giteaClient.SetBasicAuth(giteaUser01, giteaUser01Password)
	giteaToken, _, err := giteaClient.CreateAccessToken(gitea.CreateAccessTokenOption{Name: "token01"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	t.Logf("created gitea user token: %s", giteaToken.Token)

	adminGWClient := gwclient.NewClient(c.Gateway.APIExposedURL, "admintoken")
	user, _, err := adminGWClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	t.Logf("created agola user: %s", user.UserName)

	token := createAgolaUserToken(ctx, t, c)

	rs, _, err := adminGWClient.CreateRemoteSource(ctx, &gwapitypes.CreateRemoteSourceRequest{
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

	tokenGWClient := gwclient.NewClient(c.Gateway.APIExposedURL, token)

	la, _, err := tokenGWClient.CreateUserLA(ctx, agolaUser01, &gwapitypes.CreateUserLARequest{
		RemoteSourceName:          "gitea",
		RemoteSourceLoginName:     giteaUser01,
		RemoteSourceLoginPassword: giteaUser01Password,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	t.Logf("created user linked account: %s", util.Dump(la))

	return giteaToken.Token, token
}

func TestCreateProject(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

	giteaToken, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

	giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

	createProject(ctx, t, giteaClient, gwClient)
}

func TestUpdateProject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		passVarsToForkedPR bool
		expectedPre        bool
		expectedPost       bool
	}{
		{
			name:               "test project update with pass-vars-to-forked-pr true",
			passVarsToForkedPR: true,
			expectedPre:        false,
			expectedPost:       true,
		},
		{
			name:               "test project update with pass-vars-to-forked-pr false",
			passVarsToForkedPR: false,
			expectedPre:        false,
			expectedPost:       false,
		},
	}

	for _, tt := range tests {
		dir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sc := setup(ctx, t, dir, withGitea(true))
		defer sc.stop()

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaToken, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

		_, project := createProject(ctx, t, giteaClient, gwClient)
		if project.PassVarsToForkedPR != tt.expectedPre {
			t.Fatalf("expected PassVarsToForkedPR %v, got %v (pre-update)", tt.expectedPre, project.PassVarsToForkedPR)
		}
		project = updateProject(ctx, t, giteaClient, gwClient, project.ID, tt.passVarsToForkedPR)
		if project.PassVarsToForkedPR != tt.expectedPost {
			t.Fatalf("expected PassVarsToForkedPR %v, got %v (port-update)", tt.expectedPost, project.PassVarsToForkedPR)
		}
	}
}

func createProject(ctx context.Context, t *testing.T, giteaClient *gitea.Client, gwClient *gwclient.Client) (*gitea.Repository, *gwapitypes.ProjectResponse) {
	giteaRepo, _, err := giteaClient.CreateRepo(gitea.CreateRepoOption{
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
			Name:  giteaUser01,
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
		Auth: &githttp.BasicAuth{
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
				Name:  giteaUser01,
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
			Auth: &githttp.BasicAuth{
				Username: giteaUser01,
				Password: remoteToken,
			},
		}); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}
}

func TestPush(t *testing.T) {
	t.Parallel()

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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true))
			defer sc.stop()

			giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

			giteaToken, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

			giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

			giteaRepo, project := createProject(ctx, t, giteaClient, gwClient)

			push(t, tt.config, giteaRepo.CloneURL, giteaToken, tt.message, false)

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
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

			runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
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

	repoDir, err := os.MkdirTemp(dir, "repo")
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
	if err := os.WriteFile(filepath.Join(dir, ".gitconfig"), []byte(gitConfigData), 0644); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	args = append([]string{"--gateway-url", gatewayURL, "--token", token, "directrun", "start", "--untracked", "false"}, args...)
	cmd := exec.Command(filepath.Join(agolaBinDir, "agola"), args...)
	cmd.Dir = repoDir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unexpected err: %v, out: %s", err, out)
	}
	t.Logf("directrun start out: %s", out)
}

func TestDirectRun(t *testing.T) {
	testDirectRun(t, true)
}

func TestDirectRunWithoutInternalServicesAuth(t *testing.T) {
	testDirectRun(t, false)
}

func testDirectRun(t *testing.T, internalServicesAuth bool) {
	t.Parallel()

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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true), withInternalServicesAuth(internalServicesAuth))
			defer sc.stop()

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "admintoken")
			user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			t.Logf("created agola user: %s", user.UserName)

			token := createAgolaUserToken(ctx, t, sc.config)

			// From now use the user token
			gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

			directRun(t, dir, config, ConfigFormatJsonnet, sc.config.Gateway.APIExposedURL, token, tt.args...)

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
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

			runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
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
	t.Parallel()

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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			if err := os.WriteFile(filepath.Join(dir, "varfile01.yml"), []byte(varfile01), 0644); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true))
			defer sc.stop()

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "admintoken")
			user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			t.Logf("created agola user: %s", user.UserName)

			token := createAgolaUserToken(ctx, t, sc.config)

			// From now use the user token
			gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

			directRun(t, dir, config, ConfigFormatJsonnet, sc.config.Gateway.APIExposedURL, token, tt.args...)

			// TODO(sgotti) add an util to wait for a run phase
			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
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

			runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			t.Logf("runs: %s", util.Dump(runs))

			if len(runs) != 1 {
				t.Fatalf("expected 1 run got: %d", len(runs))
			}

			run, _, err := gwClient.GetUserRun(ctx, user.ID, runs[0].Number)
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

			resp, err := gwClient.GetUserLogs(ctx, user.ID, run.Number, task.ID, false, 1, false)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			defer resp.Body.Close()

			logs, err := io.ReadAll(resp.Body)
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
	t.Parallel()

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
			err:  util.NewRemoteError(util.ErrNotExist, "", ""),
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
			err:    util.NewRemoteError(util.ErrNotExist, "", ""),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true))
			defer sc.stop()

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "admintoken")
			user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			t.Logf("created agola user: %s", user.UserName)

			token := createAgolaUserToken(ctx, t, sc.config)

			// From now use the user token
			gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

			directRun(t, dir, config, ConfigFormatJsonnet, sc.config.Gateway.APIExposedURL, token)

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
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

			runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			t.Logf("runs: %s", util.Dump(runs))

			if len(runs) != 1 {
				t.Fatalf("expected 1 run got: %d", len(runs))
			}

			run, _, err := gwClient.GetUserRun(ctx, user.ID, runs[0].Number)
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
				t, _, err := gwClient.GetUserRunTask(ctx, user.ID, runs[0].Number, task.ID)
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
				_, err = gwClient.DeleteUserLogs(ctx, user.ID, run.Number, task.ID, tt.setup, tt.step)
			} else {
				_, err = gwClient.GetUserLogs(ctx, user.ID, run.Number, task.ID, tt.setup, tt.step, false)
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
	t.Parallel()

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
			name:               "test PR from same repo with PassVarsToForkedPR set to false",
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true))
			defer sc.stop()

			giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

			giteaToken, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

			giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

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
				t.Fatalf("failed to create project secret: %v", err)
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
				t.Fatalf("failed to create project variable: %v", err)
			}

			if tt.prFromSameRepo {
				// create PR from branch on same repo
				push(t, config, giteaRepo.CloneURL, giteaToken, "commit", true)

				// Looks like there're some async handlings in gitea when pushing and then instantly creating a pull request that could fail with a 404 Not found
				// We tried with a wait, before pr creation, to check that the branch exists but this always returns true also if the pr creation then fails.
				// So retry the creation for some time on 404

				prOpts := gitea.CreatePullRequestOption{
					Head:  "new-branch",
					Base:  "master",
					Title: "add file1 from new-branch on same repo",
				}

				err := testutil.Wait(10*time.Second, func() (bool, error) {
					_, resp, err := giteaClient.CreatePullRequest(giteaUser01, "repo01", prOpts)
					if err != nil {
						if resp.StatusCode == http.StatusNotFound {
							return false, nil
						}
						return false, errors.WithStack(err)
					}

					return true, nil
				})
				if err != nil {
					t.Fatalf("failed to create pull request: %v", err)
				}
			} else {
				// create PR from forked repo
				push(t, config, giteaRepo.CloneURL, giteaToken, "commit", false)

				userOpts := gitea.CreateUserOption{
					Username:           giteaUser02,
					Password:           giteaUser02Password,
					Email:              "user02@example.com",
					MustChangePassword: util.BoolP(false),
				}
				_, _, err := giteaClient.AdminCreateUser(userOpts)
				if err != nil {
					t.Fatalf("failed to create user02: %v", err)
				}

				giteaClient.SetBasicAuth(giteaUser02, giteaUser02Password)
				giteaUser02Token, _, err := giteaClient.CreateAccessToken(gitea.CreateAccessTokenOption{Name: "token01"})
				if err != nil {
					t.Fatalf("failed to create token for user02: %v", err)
				}

				giteaUser02Client, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaUser02Token.Token))
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				giteaForkedRepo, _, err := giteaUser02Client.CreateFork(giteaUser01, "repo01", gitea.CreateForkOption{})
				if err != nil {
					t.Fatalf("failed to fork repo01: %v", err)
				}

				gitfs := memfs.New()
				r, err := git.Clone(memory.NewStorage(), gitfs, &git.CloneOptions{
					Auth: &githttp.BasicAuth{
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
					Auth: &githttp.BasicAuth{
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
				_, _, err = giteaUser02Client.CreatePullRequest(giteaUser01, "repo01", prOpts)
				if err != nil {
					t.Fatalf("failed to create pull request: %v", err)
				}
			}
			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
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

			runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			t.Logf("runs: %s", util.Dump(runs))

			run, _, err := gwClient.GetProjectRun(ctx, project.ID, runs[0].Number)
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
				resp, err := gwClient.GetProjectLogs(ctx, project.ID, run.Number, task.ID, false, 1, false)
				if err != nil {
					t.Fatalf("failed to get log: %v", err)
				}
				defer resp.Body.Close()

				mypassword, err := io.ReadAll(resp.Body)
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
	t.Parallel()

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
		configFormat := configFormat
		for _, tt := range tests {
			tt := tt
			t.Run(fmt.Sprintf("%s with %s config", tt.name, configFormat), func(t *testing.T) {
				t.Parallel()

				var config string
				switch configFormat {
				case ConfigFormatJsonnet:
					config = jsonnetConfig
				case ConfigFormatStarlark:
					config = starlarkConfig
				}

				dir := t.TempDir()

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				sc := setup(ctx, t, dir, withGitea(true))
				defer sc.stop()

				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "admintoken")
				user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				t.Logf("created agola user: %s", user.UserName)

				token := createAgolaUserToken(ctx, t, sc.config)

				// From now use the user token
				gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

				directRun(t, dir, config, configFormat, sc.config.Gateway.APIExposedURL, token, tt.args...)

				// TODO(sgotti) add an util to wait for a run phase
				_ = testutil.Wait(30*time.Second, func() (bool, error) {
					runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
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

				runs, _, err := gwClient.GetUserRuns(ctx, user.ID, nil, nil, 0, 0, false)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				t.Logf("runs: %s", util.Dump(runs))

				if len(runs) != 1 {
					t.Fatalf("expected 1 run got: %d", len(runs))
				}

				run, _, err := gwClient.GetUserRun(ctx, user.ID, runs[0].Number)
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

				resp, err := gwClient.GetUserLogs(ctx, user.ID, run.Number, task.ID, false, 1, false)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				defer resp.Body.Close()

				logs, err := io.ReadAll(resp.Body)
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

func TestUserOrgs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "admintoken")

	org01, _, err := gwClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	org02, _, err := gwClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg02, Visibility: gwapitypes.VisibilityPrivate})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_, _, err = gwClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg03, Visibility: gwapitypes.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	_, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

	_, _, err = gwClient.AddOrgMember(ctx, agolaOrg01, giteaUser01, gwapitypes.MemberRoleMember)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_, _, err = gwClient.AddOrgMember(ctx, agolaOrg02, giteaUser01, gwapitypes.MemberRoleOwner)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	gwClientNew := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

	orgs, _, err := gwClientNew.GetUserOrgs(ctx)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	expectedOrgs := []*gwapitypes.UserOrgsResponse{
		{
			Organization: &gwapitypes.OrgResponse{ID: org01.ID, Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic},
			Role:         gwapitypes.MemberRoleMember,
		},

		{
			Organization: &gwapitypes.OrgResponse{ID: org02.ID, Name: agolaOrg02, Visibility: gwapitypes.VisibilityPrivate},
			Role:         gwapitypes.MemberRoleOwner,
		},
	}

	if diff := cmp.Diff(expectedOrgs, orgs); diff != "" {
		t.Fatalf("user orgs mismatch (-want +got):\n%s", diff)
	}
}

func TestTaskTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		config               string
		tasksResultExpected  map[string]rstypes.RunTaskStatus
		taskTimedoutExpected map[string]bool
	}{
		{
			name:                 "test timeout string value",
			tasksResultExpected:  map[string]rstypes.RunTaskStatus{"task01": rstypes.RunTaskStatusFailed},
			taskTimedoutExpected: map[string]bool{"task01": true},
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
					  task_timeout_interval: "15s",
					  steps: [
						  { type: 'run', command: 'sleep 30' },
					  ],
					},
				  ],
				},
			  ],
			}
		  `,
		},
		{
			name:                 "test timeout int value",
			tasksResultExpected:  map[string]rstypes.RunTaskStatus{"task01": rstypes.RunTaskStatusFailed},
			taskTimedoutExpected: map[string]bool{"task01": true},
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
					  task_timeout_interval: 15000000000,
					  steps: [
						  { type: 'run', command: 'sleep 30' },
					  ],
					},
				  ],
				},
			  ],
			}
		  `,
		},
		{
			name:                 "test timeout child timeout",
			tasksResultExpected:  map[string]rstypes.RunTaskStatus{"task01": rstypes.RunTaskStatusSuccess, "task02": rstypes.RunTaskStatusFailed},
			taskTimedoutExpected: map[string]bool{"task01": false, "task02": true},
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
						  { type: 'run', command: 'sleep 30' },
					  ],
					},
					{
						name: 'task02',
						depends: ['task01'],
						runtime: {
						  containers: [
							{
							  image: 'alpine/git',
							},
						  ],
						},
						task_timeout_interval: "15s",
						steps: [
							{ type: 'run', command: 'sleep 30' },
						],
					  },
				  ],
				},
			  ],
			}
		  `,
		},
		{
			name:                 "test timeout parent timeout",
			tasksResultExpected:  map[string]rstypes.RunTaskStatus{"task01": rstypes.RunTaskStatusFailed, "task02": rstypes.RunTaskStatusSkipped},
			taskTimedoutExpected: map[string]bool{"task01": true, "task02": false},
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
					  task_timeout_interval: "15s",
					  steps: [
						  { type: 'run', command: 'sleep 30' },
					  ],
					},
					{
						name: 'task02',
						depends: ['task01'],
						runtime: {
						  containers: [
							{
							  image: 'alpine/git',
							},
						  ],
						},
						steps: [
							{ type: 'run', command: 'sleep 30' },
						],
					  },
				  ],
				},
			  ],
			}
		  `,
		},
		{
			name:                 "test timeout parent and child timeout",
			tasksResultExpected:  map[string]rstypes.RunTaskStatus{"task01": rstypes.RunTaskStatusFailed, "task02": rstypes.RunTaskStatusSkipped},
			taskTimedoutExpected: map[string]bool{"task01": true, "task02": false},
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
					  task_timeout_interval: "15s",
					  steps: [
						  { type: 'run', command: 'sleep 30' },
					  ],
					},
					{
						name: 'task02',
						depends: ['task01'],
						runtime: {
						  containers: [
							{
							  image: 'alpine/git',
							},
						  ],
						},
						task_timeout_interval: "15s",
						steps: [
							{ type: 'run', command: 'sleep 30' },
						],
					  },
				  ],
				},
			  ],
			}
		  `,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true))
			defer sc.stop()

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, "admintoken")
			user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			t.Logf("created agola user: %s", user.UserName)

			token := createAgolaUserToken(ctx, t, sc.config)

			// From now use the user token
			gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

			directRun(t, dir, tt.config, ConfigFormatJsonnet, sc.config.Gateway.APIExposedURL, token)

			time.Sleep(30 * time.Second)

			_ = testutil.Wait(120*time.Second, func() (bool, error) {
				run, _, err := gwClient.GetUserRun(ctx, user.ID, 1)
				if err != nil {
					return false, nil
				}

				if run == nil {
					return false, nil
				}

				if run.Phase != rstypes.RunPhaseFinished {
					return false, nil
				}

				return true, nil
			})

			run, _, err := gwClient.GetUserRun(ctx, user.ID, 1)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			t.Logf("runs: %s", util.Dump(run))

			if run == nil {
				t.Fatalf("user run not found")
			}
			if run.Phase != rstypes.RunPhaseFinished {
				t.Fatalf("expected run finished got: %s", run.Phase)
			}
			if run.Result != rstypes.RunResultFailed {
				t.Fatalf("expected run failed")
			}
			if len(run.Tasks) != len(tt.tasksResultExpected) {
				t.Fatalf("expected 1 task got: %d", len(run.Tasks))
			}
			for _, task := range run.Tasks {
				if task.Status != tt.tasksResultExpected[task.Name] {
					t.Fatalf("expected task status %s got: %s", tt.tasksResultExpected[task.Name], task.Status)
				}
				if task.Timedout != tt.taskTimedoutExpected[task.Name] {
					t.Fatalf("expected task timedout %v got: %v", tt.taskTimedoutExpected[task.Name], task.Timedout)
				}
			}
		})
	}
}

func TestRefreshRemoteRepositoryInfo(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

	giteaToken, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

	giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

	giteaRepo, project := createProject(ctx, t, giteaClient, gwClient)

	if project.DefaultBranch != "master" {
		t.Fatalf("expected DefaultBranch master got: %s", project.DefaultBranch)
	}

	_, _, err = giteaClient.EditRepo(giteaRepo.Owner.UserName, giteaRepo.Name, gitea.EditRepoOption{DefaultBranch: util.StringP("testbranch")})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	project, _, err = gwClient.RefreshRemoteRepo(ctx, project.ID)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if project.DefaultBranch != "testbranch" {
		t.Fatalf("expected DefaultBranch testbranch got: %s", project.DefaultBranch)
	}

	p, _, err := gwClient.GetProject(ctx, project.ID)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(project, p); diff != "" {
		t.Fatalf("projects mismatch (-expected +got):\n%s", diff)
	}
}

func TestAddUpdateOrgUserMembers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	user, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	_, _, err = gwClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	//test add org member role member
	_, _, err = gwClient.AddOrgMember(ctx, agolaOrg01, agolaUser01, gwapitypes.MemberRoleMember)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	expectedOrgMember := gwapitypes.OrgMemberResponse{
		User: &gwapitypes.UserResponse{ID: user.ID, UserName: user.UserName},
		Role: gwapitypes.MemberRoleMember,
	}

	orgMembers, _, err := gwClient.GetOrgMembers(ctx, agolaOrg01)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if orgMembers == nil {
		t.Fatal("unexpected members nil")
	}
	if len(orgMembers.Members) != 1 {
		t.Fatalf("expected Members len 1, got: %d", len(orgMembers.Members))
	}
	if diff := cmp.Diff(*orgMembers.Members[0], expectedOrgMember); diff != "" {
		t.Fatalf("org member mismatch (-expected +got):\n%s", diff)
	}

	//test update org member role owner
	_, _, err = gwClient.AddOrgMember(ctx, agolaOrg01, agolaUser01, gwapitypes.MemberRoleOwner)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	expectedOrgMember.Role = gwapitypes.MemberRoleOwner

	orgMembers, _, err = gwClient.GetOrgMembers(ctx, agolaOrg01)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if orgMembers == nil {
		t.Fatal("unexpected members nil")
	}
	if len(orgMembers.Members) != 1 {
		t.Fatalf("expected Members len 1, got: %d", len(orgMembers.Members))
	}
	if diff := cmp.Diff(*orgMembers.Members[0], expectedOrgMember); diff != "" {
		t.Fatalf("org member mismatch (-expected +got):\n%s", diff)
	}
}

func TestUpdateOrganization(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	gwAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	//create user01 and user02
	_, _, err := gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	tokenUser01, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser01, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	gwClientUser01 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01.Token)

	_, _, err = gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	tokenUser02, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser02, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	gwClientUser02 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser02.Token)

	//create org
	org, _, err := gwClientUser01.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	//user owner update org
	expectedOrgResponse := &gwapitypes.OrgResponse{ID: org.ID, Name: agolaOrg01, Visibility: gwapitypes.VisibilityPrivate}

	visibility := gwapitypes.VisibilityPrivate
	updatedOrg, _, err := gwClientUser01.UpdateOrg(ctx, agolaOrg01, &gwapitypes.UpdateOrgRequest{Visibility: &visibility})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(updatedOrg, expectedOrgResponse); diff != "" {
		t.Fatalf("org mismatch (-want +got):\n%s", diff)
	}

	org, _, err = gwClientUser01.GetOrg(ctx, agolaOrg01)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(expectedOrgResponse, org); diff != "" {
		t.Fatalf("org mismatch (-want +got):\n%s", diff)
	}

	//user member update org
	visibility = gwapitypes.VisibilityPrivate
	_, _, err = gwClientUser02.UpdateOrg(ctx, agolaOrg01, &gwapitypes.UpdateOrgRequest{Visibility: &visibility})
	expectedErr := "remote error forbidden"
	if err == nil {
		t.Fatalf("expected error %v, got nil err", expectedErr)
	}
	if err.Error() != expectedErr {
		t.Fatalf("expected err %v, got err: %v", expectedErr, err)
	}

	org, _, err = gwClientUser01.GetOrg(ctx, agolaOrg01)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(expectedOrgResponse, org); diff != "" {
		t.Fatalf("org mismatch (-want +got):\n%s", diff)
	}
}

type testOrgInvitationConfig struct {
	sc             *setupContext
	tokenUser01    string
	tokenUser02    string
	gwAdminClient  *gwclient.Client
	gwClientUser01 *gwclient.Client
	gwClientUser02 *gwclient.Client
}

func TestOrgInvitation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		orgInvitationEnabled bool
		f                    func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig)
	}{
		{
			name:                 "test create org invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				invitation, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				i, _, err := tc.gwClientUser01.GetOrgInvitation(ctx, agolaOrg01, agolaUser02)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if diff := cmp.Diff(i, invitation); diff != "" {
					t.Fatalf("invitation mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name:                 "test user org invitation creation with already existing invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, _, err = tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				expectedErr := "remote error internal"
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
		{
			name:                 "test get user invitations",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				invitation, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, _, err = tc.gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser03})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, _, err = tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser03, Role: cstypes.MemberRoleMember})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				userInvitations, _, err := tc.gwClientUser02.GetUserOrgInvitations(ctx)
				expectedUserInvitations := []*gwapitypes.OrgInvitationResponse{invitation}
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if len(userInvitations) != 1 {
					t.Fatalf("expected 1 invitation got: %d", len(userInvitations))
				}
				if diff := cmp.Diff(expectedUserInvitations, userInvitations); diff != "" {
					t.Fatalf("user invitations mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name:                 "test user not owner create invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser02.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser01, Role: cstypes.MemberRoleMember})
				expectedErr := "remote error forbidden"
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
		{
			name:                 "test user reject invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, err = tc.gwClientUser02.UserOrgInvitationAction(ctx, agolaOrg01, &gwapitypes.OrgInvitationActionRequest{Action: csapitypes.Reject})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, _, err = tc.gwClientUser02.GetOrgInvitation(ctx, agolaOrg01, agolaUser02)
				expectedErr := "remote error notexist"
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
		{
			name:                 "test user owner delete invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, err = tc.gwClientUser01.DeleteOrgInvitation(ctx, agolaOrg01, agolaUser02)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, _, err = tc.gwClientUser01.GetOrgInvitation(ctx, agolaOrg01, agolaUser02)
				expectedErr := "remote error notexist"
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
		{
			name:                 "test user accept invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, err = tc.gwClientUser02.UserOrgInvitationAction(ctx, agolaOrg01, &gwapitypes.OrgInvitationActionRequest{Action: csapitypes.Accept})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, _, err = tc.gwClientUser02.GetOrgInvitation(ctx, agolaOrg01, agolaUser02)
				expectedErr := "remote error notexist"
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}

				org01Members, _, err := tc.gwClientUser01.GetOrgMembers(ctx, agolaOrg01)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if len(org01Members.Members) != 2 {
					t.Fatalf("expected 2 members got: %d", len(org01Members.Members))
				}
			},
		},
		{
			name:                 "test create invitation org not exists",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg02, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				expectedErr := "remote error notexist"
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
		{
			name:                 "test create invitation user already org member",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, err = tc.gwClientUser02.UserOrgInvitationAction(ctx, agolaOrg01, &gwapitypes.OrgInvitationActionRequest{Action: csapitypes.Accept})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, _, err = tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				expectedErr := "remote error internal"
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
		{
			name:                 "test create invitation user doesn't exist",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser03, Role: cstypes.MemberRoleMember})
				expectedErr := "remote error notexist"
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
		{
			name:                 "test user deletion with existing org invitations",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, err = tc.gwAdminClient.DeleteUser(ctx, agolaUser02)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				org01Invitations, _, err := tc.gwClientUser01.GetOrgInvitations(ctx, agolaOrg01)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if len(org01Invitations) != 0 {
					t.Fatalf("expected org01 invitations len 0, found: %d", len(org01Invitations))
				}
			},
		},
		{
			name:                 "test org deletion with existing org invitations",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, err = tc.gwClientUser01.DeleteOrg(ctx, agolaOrg01)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				orgInvitations, _, err := tc.gwClientUser01.GetOrgInvitations(ctx, agolaOrg01)
				expectedErr := "remote error internal"
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if len(orgInvitations) != 0 {
					t.Fatalf("expected org invitations len 0, found: %d", len(orgInvitations))
				}
			},
		},
		{
			name:                 "test create org invitation and accept after invitations disabled",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				// disable invitations in agola config
				tc.sc.config.Gateway.OrganizationMemberAddingMode = config.OrganizationMemberAddingModeInvitation
				err = tc.sc.restartAgola()
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				gwClientUser01 := gwclient.NewClient(tc.sc.config.Gateway.APIExposedURL, tc.tokenUser01)
				gwClientUser02 := gwclient.NewClient(tc.sc.config.Gateway.APIExposedURL, tc.tokenUser02)

				_, err = gwClientUser02.UserOrgInvitationAction(ctx, agolaOrg01, &gwapitypes.OrgInvitationActionRequest{Action: csapitypes.Accept})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, _, err = gwClientUser01.GetOrgInvitation(ctx, agolaOrg01, agolaUser02)
				expectedErr := "remote error notexist"
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}

				orgMembers, _, err := gwClientUser01.GetOrgMembers(ctx, agolaOrg01)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if len(orgMembers.Members) != 2 {
					t.Fatalf("expected 2 members got: %d", len(orgMembers.Members))
				}
			},
		},
		{
			name:                 "test user owner create org invitation with invitations disabled",
			orgInvitationEnabled: false,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				expectedErr := "remote error badrequest"
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
		{
			name:                 "test user owner add org member directly with invitations enabled",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.AddOrgMember(ctx, agolaOrg01, agolaUser02, gwapitypes.MemberRoleMember)
				expectedErr := "remote error badrequest"
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
		{
			name:                 "test user owner add org member with existing org invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				// disable invitations in agola config
				tc.sc.config.Gateway.OrganizationMemberAddingMode = config.OrganizationMemberAddingModeDirect
				err = tc.sc.restartAgola()
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				gwClientUser01 := gwclient.NewClient(tc.sc.config.Gateway.APIExposedURL, tc.tokenUser01)

				_, _, err = gwClientUser01.AddOrgMember(ctx, agolaOrg01, agolaUser02, gwapitypes.MemberRoleMember)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				orgInvitations, _, err := gwClientUser01.GetOrgInvitations(ctx, agolaOrg01)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if len(orgInvitations) != 0 {
					t.Fatalf("expected org invitations len 0, found: %d", len(orgInvitations))
				}
			},
		},
		{
			name:                 "test user admin add org member directly with existing org invitation",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, _, err = tc.gwAdminClient.AddOrgMember(ctx, agolaOrg01, agolaUser02, gwapitypes.MemberRoleMember)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				orgInvitations, _, err := tc.gwClientUser01.GetOrgInvitations(ctx, agolaOrg01)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if len(orgInvitations) != 0 {
					t.Fatalf("expected org invitations len 0, found: %d", len(orgInvitations))
				}
			},
		},
		{
			name:                 "test user owner get org invitations",
			orgInvitationEnabled: true,
			f: func(ctx context.Context, t *testing.T, tc *testOrgInvitationConfig) {
				_, _, err := tc.gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser03})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, _, err = tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser02, Role: cstypes.MemberRoleMember})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, _, err = tc.gwClientUser01.CreateOrgInvitation(ctx, agolaOrg01, &gwapitypes.CreateOrgInvitationRequest{UserRef: agolaUser03, Role: cstypes.MemberRoleMember})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				orgInvitations, _, err := tc.gwClientUser01.GetOrgInvitations(ctx, agolaOrg01)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if len(orgInvitations) != 2 {
					t.Fatalf("expected org invitations len 1, found: %d", len(orgInvitations))
				}

				_, _, err = tc.gwClientUser02.GetOrgInvitations(ctx, agolaOrg01)
				expectedErr := "remote error forbidden"
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var sc *setupContext
			if tt.orgInvitationEnabled {
				sc = setup(ctx, t, dir, withOrganizationMemberAddingMode(config.OrganizationMemberAddingModeInvitation))
			} else {
				sc = setup(ctx, t, dir)
			}
			defer sc.stop()

			gwAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

			_, _, err := gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			tokenUser01, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser01, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			_, _, err = gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			tokenUser02, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser02, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			_, _, err = gwAdminClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			_, _, err = gwAdminClient.AddOrgMember(ctx, agolaOrg01, agolaUser01, gwapitypes.MemberRoleOwner)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			gwClientUser01 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01.Token)
			gwClientUser02 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser02.Token)

			tc := &testOrgInvitationConfig{
				sc:             sc,
				tokenUser01:    tokenUser01.Token,
				tokenUser02:    tokenUser02.Token,
				gwClientUser01: gwClientUser01,
				gwClientUser02: gwClientUser02,
				gwAdminClient:  gwAdminClient,
			}

			tt.f(ctx, t, tc)
		})
	}
}

func TestGetUsers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		f    func(ctx context.Context, t *testing.T, sc *setupContext)
	}{
		{
			name: "test admin get user by remoteuserid and remotesourceref",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				createLinkedAccount(ctx, t, sc.gitea, sc.config)

				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				user, _, err := gwClient.GetUserByLinkedAccountRemoteUserAndSource(ctx, "1", "gitea")
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if user.UserName != giteaUser01 {
					t.Fatalf("expected username %s, got %s", giteaUser01, user.UserName)
				}
			},
		},
		{
			name: "test user get user by remoteuserid and remotesourceref",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				_, user01Token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, user01Token)

				_, _, err := gwClient.GetUserByLinkedAccountRemoteUserAndSource(ctx, "1", "gitea")
				expectedErr := "remote error unauthorized"
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
		{
			name: "test admin get users",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				user01, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				user02, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				expectedUsers := []*gwapitypes.PrivateUserResponse{
					{ID: user01.ID, UserName: user01.UserName, Tokens: []string{}, LinkedAccounts: []*gwapitypes.LinkedAccountResponse{}},
					{ID: user02.ID, UserName: user02.UserName, Tokens: []string{}, LinkedAccounts: []*gwapitypes.LinkedAccountResponse{}},
				}
				users, _, err := gwClient.GetUsers(ctx, "", 0, true)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if diff := cmp.Diff(expectedUsers, users); diff != "" {
					t.Fatalf("users mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name: "test user get users",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				_, user01Token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, user01Token)

				_, _, err := gwClient.GetUsers(ctx, "", 0, true)
				expectedErr := "remote error unauthorized"
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true))
			defer sc.stop()

			tt.f(ctx, t, sc)
		})
	}
}

func TestMaintenance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		f    func(ctx context.Context, t *testing.T, sc *setupContext)
	}{
		{
			name: "test admin user enable maintenance",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				_, err := gwClient.EnableMaintenance(ctx, configstoreService)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, err = gwClient.EnableMaintenance(ctx, runserviceService)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
			},
		},
		{
			name: "test user enable maintenance",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				_, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				token, _, err := gwClient.CreateUserToken(ctx, agolaUser01, &gwapitypes.CreateUserTokenRequest{TokenName: "tokenuser01"})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, token.Token)

				expectedErr := "remote error unauthorized"
				_, err = gwClient.EnableMaintenance(ctx, configstoreService)
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}

				_, err = gwClient.EnableMaintenance(ctx, runserviceService)
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
		{
			name: "test user disable maintenance",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				_, _, err := gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				token, _, err := gwClient.CreateUserToken(ctx, agolaUser01, &gwapitypes.CreateUserTokenRequest{TokenName: "tokenuser01"})
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, token.Token)

				expectedErr := "remote error unauthorized"
				_, err = gwClient.DisableMaintenance(ctx, configstoreService)
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}

				_, err = gwClient.DisableMaintenance(ctx, runserviceService)
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
		{
			name: "test admin user enable maintenance already enabled",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				_, err := gwClient.EnableMaintenance(ctx, configstoreService)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, err = gwClient.EnableMaintenance(ctx, runserviceService)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_ = testutil.Wait(30*time.Second, func() (bool, error) {
					maintenanceStatus, _, err := gwClient.GetMaintenanceStatus(ctx, configstoreService)
					if err != nil {
						return false, nil
					}
					if !maintenanceStatus.CurrentStatus {
						return false, nil
					}

					maintenanceStatus, _, err = gwClient.GetMaintenanceStatus(ctx, runserviceService)
					if err != nil {
						return false, nil
					}
					if !maintenanceStatus.CurrentStatus {
						return false, nil
					}

					return true, nil
				})

				expectedErr := "remote error badrequest"
				_, err = gwClient.EnableMaintenance(ctx, configstoreService)
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}

				_, err = gwClient.EnableMaintenance(ctx, runserviceService)
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
		{
			name: "test admin user disable maintenance",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				_, err := gwClient.EnableMaintenance(ctx, configstoreService)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_ = testutil.Wait(30*time.Second, func() (bool, error) {
					maintenanceStatus, _, err := gwClient.GetMaintenanceStatus(ctx, configstoreService)
					if err != nil {
						return false, nil
					}
					if !maintenanceStatus.CurrentStatus {
						return false, nil
					}

					return true, nil
				})

				_, err = gwClient.DisableMaintenance(ctx, configstoreService)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, err = gwClient.EnableMaintenance(ctx, runserviceService)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_ = testutil.Wait(30*time.Second, func() (bool, error) {
					maintenanceStatus, _, err := gwClient.GetMaintenanceStatus(ctx, runserviceService)
					if err != nil {
						return false, nil
					}
					if !maintenanceStatus.CurrentStatus {
						return false, nil
					}

					return true, nil
				})

				_, err = gwClient.DisableMaintenance(ctx, runserviceService)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
			},
		},
		{
			name: "test admin user disable maintenance already disabled",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				expectedErr := "remote error badrequest"
				_, err := gwClient.DisableMaintenance(ctx, configstoreService)
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}

				_, err = gwClient.DisableMaintenance(ctx, runserviceService)
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
		{
			name: "test wrong provided servicename",
			f: func(ctx context.Context, t *testing.T, sc *setupContext) {
				gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

				expectedErr := "remote error badrequest"
				_, err := gwClient.EnableMaintenance(ctx, "test")
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}

				_, err = gwClient.DisableMaintenance(ctx, "test")
				if err == nil {
					t.Fatalf("expected error %v, got nil err", expectedErr)
				}
				if err.Error() != expectedErr {
					t.Fatalf("expected err %v, got err: %v", expectedErr, err)
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir)
			defer sc.stop()

			tt.f(ctx, t, sc)
		})
	}
}

func TestExportImport(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

	giteaToken, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

	giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

	giteaRepo, project := createProject(ctx, t, giteaClient, gwClient)

	config := `
				{
					runs: [
					  {
						name: 'run01',
						tasks: [
							{
							name: 'task01',
							runtime: {
								containers: [{
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
				}`

	push(t, config, giteaRepo.CloneURL, giteaToken, "commit", false)

	_ = testutil.Wait(30*time.Second, func() (bool, error) {
		runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
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

	runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("expected %d run got: %d", 1, len(runs))
	}

	gwClient = gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	users, _, err := gwClient.GetUsers(ctx, "", 0, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	projectgroup, _, err := gwClient.GetProjectGroup(ctx, "user/user01")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	remotesources, _, err := gwClient.GetRemoteSources(ctx, "", 0, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	user01Projects, _, err := gwClient.GetProjectGroupProjects(ctx, "user/user01")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	w, err := os.Create(filepath.Join(dir, "export-configstore"))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	resp, err := gwClient.Export(ctx, configstoreService)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	w, err = os.Create(filepath.Join(dir, "export-runservice"))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	resp, err = gwClient.Export(ctx, runserviceService)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	//add some data
	_, _, err = gwClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_, _, err = gwClient.CreateRemoteSource(ctx, &gwapitypes.CreateRemoteSourceRequest{
		Name:                "github",
		Type:                "gitea",
		APIURL:              giteaAPIURL,
		AuthType:            "password",
		SkipSSHHostKeyCheck: true,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	_, _, err = gwClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	_, err = gwClient.EnableMaintenance(ctx, configstoreService)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	_, err = gwClient.EnableMaintenance(ctx, runserviceService)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	_ = testutil.Wait(30*time.Second, func() (bool, error) {
		maintenanceStatus, _, err := gwClient.GetMaintenanceStatus(ctx, configstoreService)
		if err != nil {
			return false, nil
		}
		if !maintenanceStatus.CurrentStatus {
			return false, nil
		}

		maintenanceStatus, _, err = gwClient.GetMaintenanceStatus(ctx, runserviceService)
		if err != nil {
			return false, nil
		}
		if !maintenanceStatus.CurrentStatus {
			return false, nil
		}

		return true, nil
	})

	r, err := os.Open(filepath.Join(dir, "export-configstore"))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	_, err = gwClient.Import(ctx, configstoreService, r)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	_, err = gwClient.DisableMaintenance(ctx, configstoreService)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	_, err = gwClient.DisableMaintenance(ctx, runserviceService)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	_ = testutil.Wait(30*time.Second, func() (bool, error) {
		maintenanceStatus, _, err := gwClient.GetMaintenanceStatus(ctx, configstoreService)
		if err != nil {
			return false, nil
		}
		if maintenanceStatus.CurrentStatus {
			return false, nil
		}

		maintenanceStatus, _, err = gwClient.GetMaintenanceStatus(ctx, runserviceService)
		if err != nil {
			return false, nil
		}
		if maintenanceStatus.CurrentStatus {
			return false, nil
		}

		return true, nil
	})

	impUsers, _, err := gwClient.GetUsers(ctx, "", 0, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(users, impUsers); diff != "" {
		t.Fatalf("users mismatch (-want +got):\n%s", diff)
	}

	impProjectgroup, _, err := gwClient.GetProjectGroup(ctx, "user/user01")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(projectgroup, impProjectgroup); diff != "" {
		t.Fatalf("projectgroup mismatch (-want +got):\n%s", diff)
	}

	impRemotesources, _, err := gwClient.GetRemoteSources(ctx, "", 0, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(remotesources, impRemotesources); diff != "" {
		t.Fatalf("remotesources mismatch (-want +got):\n%s", diff)
	}

	impUser01Projects, _, err := gwClient.GetProjectGroupProjects(ctx, "user/user01")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(user01Projects, impUser01Projects); diff != "" {
		t.Fatalf("user01 projects mismatch (-want +got):\n%s", diff)
	}

	impRuns, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(runs, impRuns); diff != "" {
		t.Fatalf("runs mismatch (-want +got):\n%s", diff)
	}

	orgs, _, err := gwClient.GetOrgs(ctx, "", 0, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(orgs) != 0 {
		t.Fatalf("expected 0 orgs got: %d", len(orgs))
	}
}

func TestGetProjectRuns(t *testing.T) {
	t.Parallel()

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
		name         string
		phaseFilter  []string
		resultFilter []string
		num          int
	}{
		{
			name: "test get all runs",
			num:  1,
		},
		{
			name:         "test get runs phase finished and result success",
			phaseFilter:  []string{"finished"},
			resultFilter: []string{"success"},
			num:          1,
		},
		{
			name:        "test get runs phase running",
			phaseFilter: []string{"running"},
			num:         0,
		},
		{
			name:         "test get runs result failed",
			resultFilter: []string{"failed"},
			num:          0,
		},
		{
			name:         "test get runs with all filters",
			phaseFilter:  []string{"setuperror", "queued", "cancelled", "running", "finished"},
			resultFilter: []string{"unknown", "stopped", "success", "failed"},
			num:          1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sc := setup(ctx, t, dir, withGitea(true))
			defer sc.stop()

			giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

			giteaToken, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

			giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

			giteaRepo, project := createProject(ctx, t, giteaClient, gwClient)

			push(t, config, giteaRepo.CloneURL, giteaToken, "commit", false)

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
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

			runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, tt.phaseFilter, tt.resultFilter, 0, 0, false)
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
			}
		})
	}
}

func TestRunEventsNotification(t *testing.T) {
	tests := []struct {
		name                   string
		config                 string
		expectedRunResult      rstypes.RunResult
		expectedRunPhase       rstypes.RunPhase
		expectedRunPhaseEvents []rstypes.RunPhase
		expectedRunTaskStatus  []rstypes.RunTaskStatus
	}{
		{
			name: "test run result success",
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
			            { type: 'run', command: 'env' },
			          ],
			        },
			      ],
			    },
			  ],
			}
			`,
			expectedRunResult:      rstypes.RunResultSuccess,
			expectedRunPhase:       rstypes.RunPhaseFinished,
			expectedRunPhaseEvents: []rstypes.RunPhase{rstypes.RunPhaseQueued, rstypes.RunPhaseRunning, rstypes.RunPhaseRunning, rstypes.RunPhaseFinished},
			expectedRunTaskStatus:  []rstypes.RunTaskStatus{rstypes.RunTaskStatusNotStarted, rstypes.RunTaskStatusNotStarted, rstypes.RunTaskStatusSuccess, rstypes.RunTaskStatusSuccess},
		},
		{
			name: "test run result failed",
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
			            { type: 'run', command: 'false' },
			          ],
			        },
			      ],
			      when: {
			        branch: 'master',
			      },
			    },
			  ],
			}
			`,
			expectedRunResult:      rstypes.RunResultFailed,
			expectedRunPhase:       rstypes.RunPhaseFinished,
			expectedRunPhaseEvents: []rstypes.RunPhase{rstypes.RunPhaseQueued, rstypes.RunPhaseRunning, rstypes.RunPhaseRunning, rstypes.RunPhaseFinished},
			expectedRunTaskStatus:  []rstypes.RunTaskStatus{rstypes.RunTaskStatusNotStarted, rstypes.RunTaskStatusNotStarted, rstypes.RunTaskStatusFailed, rstypes.RunTaskStatusFailed},
		},
		{
			name: "test run setup config error",
			config: `
				{
				  runserror:
				}
				`,
			expectedRunResult:      rstypes.RunResultUnknown,
			expectedRunPhase:       rstypes.RunPhaseSetupError,
			expectedRunPhaseEvents: []rstypes.RunPhase{rstypes.RunPhaseSetupError},
			expectedRunTaskStatus:  []rstypes.RunTaskStatus{rstypes.RunTaskStatusNotStarted},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			wrDir := t.TempDir()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			wr := setupWebhooksReceiver(ctx, t, wrDir)
			defer wr.stop()

			sc := setup(ctx, t, dir, withGitea(true), withWebhooks(fmt.Sprintf("%s/%s", wr.exposedURL, "webhooks"), "secretkey"))
			defer sc.stop()

			giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)

			giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

			giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)

			giteaRepo, project := createProject(ctx, t, giteaClient, gwClient)

			push(t, tt.config, giteaRepo.CloneURL, giteaToken, "commit", false)

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
				if err != nil {
					return false, nil
				}

				if len(runs) == 0 {
					return false, nil
				}
				if runs[0].Phase != tt.expectedRunPhase {
					return false, nil
				}

				return true, nil
			})

			runs, _, err := gwClient.GetProjectRuns(ctx, project.ID, nil, nil, 0, 0, false)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if len(runs) != 1 {
				t.Fatalf("expected %d run got: %d", 1, len(runs))
			}

			if runs[0].Phase != tt.expectedRunPhase {
				t.Fatalf("expected run phase %q, got %q", tt.expectedRunPhase, runs[0].Phase)
			}
			if runs[0].Result != tt.expectedRunResult {
				t.Fatalf("expected run result %q, got %q", tt.expectedRunResult, runs[0].Result)
			}

			run, _, err := gwClient.GetProjectRun(ctx, project.ID, runs[0].Number)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			_ = testutil.Wait(30*time.Second, func() (bool, error) {
				webhooks, err := wr.webhooks.getWebhooks()
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if len(webhooks) < len(tt.expectedRunPhaseEvents) {
					return false, nil
				}

				return true, nil
			})

			webhooks, err := wr.webhooks.getWebhooks()
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			for i, w := range webhooks {
				data, err := json.Marshal(w.webhookData)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				sig256 := hmac.New(sha256.New, []byte(sc.config.Notification.WebhookSecret))
				_, err = io.MultiWriter(sig256).Write(data)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				signatureSHA256 := hex.EncodeToString(sig256.Sum(nil))
				if signatureSHA256 != w.signature {
					t.Fatalf("expected webhook signature %q, got %q", signatureSHA256, w.signature)
				}

				if w.webhookData.Run.Counter != run.Number {
					t.Fatalf("expected webhook run counter %q, got %q", run.Number, w.webhookData.Run.Counter)
				}
				if w.webhookData.Run.Name != run.Name {
					t.Fatalf("expected webhook run name %q, got %q", run.Name, w.webhookData.Run.Name)
				}
				if w.webhookData.Run.Phase != string(tt.expectedRunPhaseEvents[i]) {
					t.Fatalf("expected webhook run phase %q, got %q", tt.expectedRunPhaseEvents[i], w.webhookData.Run.Phase)
				}
				if len(w.webhookData.Run.Tasks) != len(run.Tasks) {
					t.Fatalf("expected %d webhook run tasks got: %d", 1, len(w.webhookData.Run.Tasks))
				}

				if len(run.Tasks) > 0 {
					var taskID string
					for id := range w.webhookData.Run.Tasks {
						taskID = id
					}
					whTask := w.webhookData.Run.Tasks[taskID]
					task := run.Tasks[taskID]

					if whTask.ID != task.ID {
						t.Fatalf("expected webhook run task id %q, got %q", task.ID, whTask.ID)
					}
					if whTask.Name != task.Name {
						t.Fatalf("expected webhook run task name %q, got %q", task.Name, whTask.Name)
					}
					if whTask.Status != string(tt.expectedRunTaskStatus[i]) {
						t.Fatalf("expected webhook run task status %q, got %q", string(tt.expectedRunTaskStatus[i]), whTask.Status)
					}
					if whTask.Approved != false {
						t.Fatalf("expected webhook run task approved %t, got %t", false, whTask.Approved)
					}
					if whTask.Skip != false {
						t.Fatalf("expected webhook run task skip %t, got %t", false, whTask.Skip)
					}
					if whTask.Timedout != false {
						t.Fatalf("expected webhook run task timedout %t, got %t", false, whTask.Timedout)
					}
					if whTask.WaitingApproval != false {
						t.Fatalf("expected webhook run task waitingApproval %t, got %t", false, whTask.Timedout)
					}
					if len(whTask.Steps) != 1 {
						t.Fatalf("expected %d webhook run task steps got: %d", 1, len(whTask.Steps))
					}
					if whTask.Level != 0 {
						t.Fatalf("expected %d webhook run task level got: %d", 1, whTask.Level)
					}
				}
			}
		})
	}
}
