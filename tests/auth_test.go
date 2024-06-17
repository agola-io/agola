package tests

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"code.gitea.io/sdk/gitea"
	"github.com/pkg/errors"
	"gotest.tools/assert"

	"agola.io/agola/internal/services/gateway/common"
	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
	gwapierrors "agola.io/agola/services/gateway/api/errors"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"
)

func TestCreateLinkedAccount(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	createLinkedAccount(ctx, t, sc.gitea, sc.config)
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
	testutil.NilError(t, err)

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
	testutil.NilError(t, err)

	t.Logf("created agola user")

	loginUserResponse, _, err := loginGWClient.Login(ctx, &gwapitypes.LoginUserRequest{
		RemoteSourceName: "gitea",
		LoginName:        giteaUser01,
		LoginPassword:    giteaUser01Password,
	})
	testutil.NilError(t, err)

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
	expectedErr := util.NewRemoteError(util.ErrBadRequest, util.WithRemoteErrorDetailedError(&util.RemoteDetailedError{Code: gwapierrors.ErrorCodeLinkedAccountAlreadyExists}))
	assert.Error(t, err, expectedErr.Error())

	// Remove user
	_, err = adminGWClient.DeleteUser(ctx, loginUserResponse.User.ID)
	testutil.NilError(t, err)

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
	testutil.NilError(t, err)

	token := createAgolaUserToken(ctx, t, sc.config)
	tokenGWClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

	// Do an agola call that will use the linkedAccount userAccessToken to call gitea api
	// should work
	_, _, err = tokenGWClient.GetUserRemoteRepos(ctx, rs.ID)
	testutil.NilError(t, err)
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
	testutil.NilError(t, err)

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
	testutil.NilError(t, err)

	t.Logf("created agola user")

	_, _, err = loginGWClient.Login(ctx, &gwapitypes.LoginUserRequest{
		RemoteSourceName: "gitea",
		LoginName:        giteaUser01,
		LoginPassword:    giteaUser01Password,
	})
	testutil.NilError(t, err)

	token := createAgolaUserToken(ctx, t, sc.config)
	tokenGWClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

	// Test userAccessToken recreation on login
	giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetBasicAuth(giteaUser01, giteaUser01Password))
	testutil.NilError(t, err)

	giteaTokens, _, err := giteaClient.ListAccessTokens(gitea.ListAccessTokensOptions{})
	testutil.NilError(t, err)

	for _, giteaToken := range giteaTokens {
		_, err := giteaClient.DeleteAccessToken(giteaToken.Name)
		testutil.NilError(t, err)
	}

	// Do an agola call that will use the linkedAccount userAccessToken to call gitea api
	// should fails since the registered token has been removed
	_, _, err = tokenGWClient.GetUserRemoteRepos(ctx, rs.ID)
	expectedErr := remoteErrorBadRequest
	assert.Error(t, err, expectedErr.Error())

	// redo login. Should create a new gitea user access token
	_, _, err = loginGWClient.Login(ctx, &gwapitypes.LoginUserRequest{
		RemoteSourceName: "gitea",
		LoginName:        giteaUser01,
		LoginPassword:    giteaUser01Password,
	})
	testutil.NilError(t, err)

	// Do an agola call that will use the linkedAccount userAccessToken to call gitea api
	// should work
	_, _, err = tokenGWClient.GetUserRemoteRepos(ctx, rs.ID)
	testutil.NilError(t, err)
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
	testutil.NilError(t, err)

	// Test auth passing received login response cookies
	authCookieName := common.AuthCookieName(false)
	secondaryAuthCookieName := common.SecondaryAuthCookieName()
	cookies := resp.Cookies()
	_, _, err = gwCookieClient.GetCurrentUser(ctx, cookies)
	testutil.NilError(t, err)

	// Don't send  authcookie
	cookies = []*http.Cookie{}
	for _, c := range resp.Cookies() {
		if c.Name == authCookieName {
			continue
		}
		cookies = append(cookies, c)
	}

	_, _, err = gwCookieClient.GetCurrentUser(ctx, cookies)
	expectedErr := remoteErrorUnauthorized
	assert.Error(t, err, expectedErr.Error())

	// Don't send secondary authcookie
	cookies = []*http.Cookie{}
	for _, c := range resp.Cookies() {
		if c.Name == secondaryAuthCookieName {
			continue
		}
		cookies = append(cookies, c)
	}

	_, _, err = gwCookieClient.GetCurrentUser(ctx, cookies)
	expectedErr = remoteErrorUnauthorized
	assert.Error(t, err, expectedErr.Error())
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
	testutil.NilError(t, err)

	loginCookies := resp.Cookies()

	// Do an initial request to fetch the csrf cookies and token
	_, resp, err = gwCookieClient.GetCurrentUser(ctx, loginCookies)
	testutil.NilError(t, err)

	t.Logf("resp.Header: %v", resp.Header)
	cookies := append(loginCookies, resp.Cookies()...)
	csrfToken := resp.Header.Get("X-Csrf-Token")
	header := http.Header{}
	header.Set("X-Csrf-Token", csrfToken)

	// Create an org. Should work
	_, _, err = gwCookieClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic}, header, cookies)
	testutil.NilError(t, err)

	// Don't send csrf token in request headers. Should return 403 (forbidden)
	_, _, err = gwCookieClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg02, Visibility: gwapitypes.VisibilityPublic}, http.Header{}, cookies)
	expectedErr := errors.Errorf("unknown api error (status: 403)")
	assert.Error(t, err, expectedErr.Error())

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
	expectedErr = errors.Errorf("unknown api error (status: 403)")
	assert.Error(t, err, expectedErr.Error())

	// Send also an Authorization token that won't match to check that csrf check is done
	header.Set("Authorization", "Token unexistenttoken")

	_, _, err = gwCookieClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg02, Visibility: gwapitypes.VisibilityPublic}, header, noCSRFCookies)
	// Now we enforce and auth error if an Authorization token is provided and
	// the user for the token doesn't exist. In future we could add ways to
	// continue other auth checkers. The error should then be the commented one.
	// expectedErr = "unknown api error (status: 403)"
	expectedErr = remoteErrorUnauthorized
	assert.Error(t, err, expectedErr.Error())
}
