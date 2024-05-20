package tests

import (
	"context"
	"fmt"
	"path"
	"testing"
	"time"

	"code.gitea.io/sdk/gitea"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
	gwapierrors "agola.io/agola/services/gateway/api/errors"
	gwapitypes "agola.io/agola/services/gateway/api/types"
	gwclient "agola.io/agola/services/gateway/client"
	rstypes "agola.io/agola/services/runservice/types"
)

func TestGetProjectGroup(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	gwAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	// create users
	_, _, err := gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser01})
	testutil.NilError(t, err)

	tokenUser01, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser01, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
	testutil.NilError(t, err)

	gwClientUser01 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01.Token)

	_, _, err = gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
	testutil.NilError(t, err)

	tokenUser02, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser02, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
	testutil.NilError(t, err)

	gwClientUser02 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser02.Token)

	_, _, err = gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser03})
	testutil.NilError(t, err)

	tokenUser03, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser03, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
	testutil.NilError(t, err)

	gwClientUser03 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser03.Token)

	// create public org
	pubOrg, _, err := gwClientUser01.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
	testutil.NilError(t, err)

	// create public org pub project group
	pubOrgPubPG, _, err := gwClientUser01.CreateProjectGroup(ctx, &gwapitypes.CreateProjectGroupRequest{Name: "puborg-pubpg", ParentRef: path.Join("org", pubOrg.Name), Visibility: gwapitypes.VisibilityPublic})
	testutil.NilError(t, err)

	// create public org priv project group
	pubOrgPrivPG, _, err := gwClientUser01.CreateProjectGroup(ctx, &gwapitypes.CreateProjectGroupRequest{Name: "puborg-privpg", ParentRef: path.Join("org", pubOrg.Name), Visibility: gwapitypes.VisibilityPrivate})
	testutil.NilError(t, err)

	// create private org
	privOrg, _, err := gwClientUser01.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg02, Visibility: gwapitypes.VisibilityPrivate})
	testutil.NilError(t, err)

	// create priv org pub project group
	privOrgPubPG, _, err := gwClientUser01.CreateProjectGroup(ctx, &gwapitypes.CreateProjectGroupRequest{Name: "privorg-pubpg", ParentRef: path.Join("org", privOrg.Name), Visibility: gwapitypes.VisibilityPublic})
	testutil.NilError(t, err)

	// create priv org priv project group
	privOrgPrivPG, _, err := gwClientUser01.CreateProjectGroup(ctx, &gwapitypes.CreateProjectGroupRequest{Name: "privorg-privpg", ParentRef: path.Join("org", privOrg.Name), Visibility: gwapitypes.VisibilityPrivate})
	testutil.NilError(t, err)

	// add user02 as member of pub org
	_, _, err = gwClientUser01.AddOrgMember(ctx, pubOrg.ID, agolaUser02, gwapitypes.MemberRoleMember)
	testutil.NilError(t, err)

	// add user02 as member of priv org
	_, _, err = gwClientUser01.AddOrgMember(ctx, privOrg.ID, agolaUser02, gwapitypes.MemberRoleMember)
	testutil.NilError(t, err)

	tests := []struct {
		name   string
		client *gwclient.Client
		pg     *gwapitypes.ProjectGroupResponse
		err    error
	}{
		{
			name:   "user owner get pub org pub pg",
			client: gwClientUser01,
			pg:     pubOrgPubPG,
		},
		{
			name:   "user member get pub org pub pg",
			client: gwClientUser02,
			pg:     pubOrgPubPG,
		},
		{
			name:   "user not member get pub org pub pg",
			client: gwClientUser03,
			pg:     pubOrgPubPG,
		},
		{
			name:   "user owner get pub org priv pg",
			client: gwClientUser01,
			pg:     pubOrgPrivPG,
		},
		{
			name:   "user member get pub org priv pg",
			client: gwClientUser02,
			pg:     pubOrgPrivPG,
		},
		{
			name:   "user not member get pub org priv pg",
			client: gwClientUser03,
			pg:     pubOrgPrivPG,
			err:    util.NewRemoteError(util.ErrNotExist, util.WithRemoteErrorDetailedError(&util.RemoteDetailedError{Code: gwapierrors.ErrorCodeOrganizationDoesNotExist})),
		},
		{
			name:   "user owner get priv org pub pg",
			client: gwClientUser01,
			pg:     privOrgPubPG,
		},
		{
			name:   "user member get priv org pub pg",
			client: gwClientUser02,
			pg:     privOrgPubPG,
		},
		{
			name:   "user not member get priv org pub pg",
			client: gwClientUser03,
			pg:     privOrgPubPG,
			err:    util.NewRemoteError(util.ErrNotExist, util.WithRemoteErrorDetailedError(&util.RemoteDetailedError{Code: gwapierrors.ErrorCodeOrganizationDoesNotExist})),
		},
		{
			name:   "user owner get priv org priv pg",
			client: gwClientUser01,
			pg:     privOrgPrivPG,
		},
		{
			name:   "user member get priv org priv pg",
			client: gwClientUser02,
			pg:     privOrgPrivPG,
		},
		{
			name:   "user not member get priv org priv pg",
			client: gwClientUser03,
			pg:     privOrgPrivPG,
			err:    util.NewRemoteError(util.ErrNotExist, util.WithRemoteErrorDetailedError(&util.RemoteDetailedError{Code: gwapierrors.ErrorCodeOrganizationDoesNotExist})),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			pg, _, err := tt.client.GetProjectGroup(ctx, tt.pg.ID)

			if tt.err != nil {
				assert.Error(t, err, tt.err.Error())
			} else {
				testutil.NilError(t, err)

				assert.DeepEqual(t, tt.pg, pg)
			}
		})
	}
}

func TestGetProject(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := setup(ctx, t, dir, withGitea(true))
	defer sc.stop()

	gwAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)

	giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)

	giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

	giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
	testutil.NilError(t, err)

	gwClientUser01 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)

	createProject(ctx, t, giteaClient, gwClientUser01)

	// create other users
	_, _, err = gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
	testutil.NilError(t, err)

	tokenUser02, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser02, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
	testutil.NilError(t, err)

	gwClientUser02 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser02.Token)

	_, _, err = gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser03})
	testutil.NilError(t, err)

	tokenUser03, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser03, &gwapitypes.CreateUserTokenRequest{TokenName: "test"})
	testutil.NilError(t, err)

	gwClientUser03 := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser03.Token)

	// create public org
	pubOrg, _, err := gwClientUser01.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
	testutil.NilError(t, err)

	// create public org pub project group
	pubOrgPubPG, _, err := gwClientUser01.CreateProjectGroup(ctx, &gwapitypes.CreateProjectGroupRequest{Name: "puborg-pubpg", ParentRef: path.Join("org", pubOrg.Name), Visibility: gwapitypes.VisibilityPublic})
	testutil.NilError(t, err)

	// create public org pub project group pub project
	pubOrgPubPGPubProj, _, err := gwClientUser01.CreateProject(ctx, &gwapitypes.CreateProjectRequest{Name: "puborg-pubpg-pugproj", ParentRef: pubOrgPubPG.ID, Visibility: gwapitypes.VisibilityPublic, RemoteSourceName: "gitea", RepoPath: path.Join(giteaUser01, "repo01")})
	testutil.NilError(t, err)

	// create public org pub project group priv project
	pubOrgPubPGPrivProj, _, err := gwClientUser01.CreateProject(ctx, &gwapitypes.CreateProjectRequest{Name: "puborg-pubpg-privproj", ParentRef: pubOrgPubPG.ID, Visibility: gwapitypes.VisibilityPrivate, RemoteSourceName: "gitea", RepoPath: path.Join(giteaUser01, "repo01")})
	testutil.NilError(t, err)

	// create public org priv project group
	pubOrgPrivPG, _, err := gwClientUser01.CreateProjectGroup(ctx, &gwapitypes.CreateProjectGroupRequest{Name: "puborg-privpg", ParentRef: path.Join("org", pubOrg.Name), Visibility: gwapitypes.VisibilityPrivate})
	testutil.NilError(t, err)

	// create public org priv project group pub project
	pubOrgPrivPGPubProj, _, err := gwClientUser01.CreateProject(ctx, &gwapitypes.CreateProjectRequest{Name: "pubvorg-privpg-pugproj", ParentRef: pubOrgPrivPG.ID, Visibility: gwapitypes.VisibilityPublic, RemoteSourceName: "gitea", RepoPath: path.Join(giteaUser01, "repo01")})
	testutil.NilError(t, err)

	// create public org priv project group priv project
	pubOrgPrivPGPrivProj, _, err := gwClientUser01.CreateProject(ctx, &gwapitypes.CreateProjectRequest{Name: "pubvorg-privpg-privproj", ParentRef: pubOrgPrivPG.ID, Visibility: gwapitypes.VisibilityPrivate, RemoteSourceName: "gitea", RepoPath: path.Join(giteaUser01, "repo01")})
	testutil.NilError(t, err)

	// create private org
	privOrg, _, err := gwClientUser01.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg02, Visibility: gwapitypes.VisibilityPrivate})
	testutil.NilError(t, err)

	// create priv org pub project group
	privOrgPubPG, _, err := gwClientUser01.CreateProjectGroup(ctx, &gwapitypes.CreateProjectGroupRequest{Name: "privorg-pubpg", ParentRef: path.Join("org", privOrg.Name), Visibility: gwapitypes.VisibilityPublic})
	testutil.NilError(t, err)

	// create priv org pub project group pub project
	privOrgPubPGPubProj, _, err := gwClientUser01.CreateProject(ctx, &gwapitypes.CreateProjectRequest{Name: "privorg-pubpg-pugproj", ParentRef: privOrgPubPG.ID, Visibility: gwapitypes.VisibilityPublic, RemoteSourceName: "gitea", RepoPath: path.Join(giteaUser01, "repo01")})
	testutil.NilError(t, err)

	// create priv org pub project group priv project
	privOrgPubPGPrivProj, _, err := gwClientUser01.CreateProject(ctx, &gwapitypes.CreateProjectRequest{Name: "privorg-pubpg-privproj", ParentRef: privOrgPubPG.ID, Visibility: gwapitypes.VisibilityPrivate, RemoteSourceName: "gitea", RepoPath: path.Join(giteaUser01, "repo01")})
	testutil.NilError(t, err)

	// create priv org priv project group
	privOrgPrivPG, _, err := gwClientUser01.CreateProjectGroup(ctx, &gwapitypes.CreateProjectGroupRequest{Name: "privorg-privpg", ParentRef: path.Join("org", privOrg.Name), Visibility: gwapitypes.VisibilityPrivate})
	testutil.NilError(t, err)

	// create priv org priv project group pub project
	privOrgPrivPGPubProj, _, err := gwClientUser01.CreateProject(ctx, &gwapitypes.CreateProjectRequest{Name: "privorg-privpg-pubproj", ParentRef: privOrgPrivPG.ID, Visibility: gwapitypes.VisibilityPublic, RemoteSourceName: "gitea", RepoPath: path.Join(giteaUser01, "repo01")})
	testutil.NilError(t, err)

	// create priv org priv project group priv project
	privOrgPrivPGPrivProj, _, err := gwClientUser01.CreateProject(ctx, &gwapitypes.CreateProjectRequest{Name: "privorg-privpg-privproj", ParentRef: privOrgPrivPG.ID, Visibility: gwapitypes.VisibilityPrivate, RemoteSourceName: "gitea", RepoPath: path.Join(giteaUser01, "repo01")})
	testutil.NilError(t, err)

	// add user02 as member of pub org
	_, _, err = gwClientUser01.AddOrgMember(ctx, pubOrg.ID, agolaUser02, gwapitypes.MemberRoleMember)
	testutil.NilError(t, err)

	// add user02 as member of priv org
	_, _, err = gwClientUser01.AddOrgMember(ctx, privOrg.ID, agolaUser02, gwapitypes.MemberRoleMember)
	testutil.NilError(t, err)

	tests := []struct {
		name   string
		client *gwclient.Client
		proj   *gwapitypes.ProjectResponse
		err    error
	}{
		{
			name:   "user owner get pub org pub pg pub proj",
			client: gwClientUser01,
			proj:   pubOrgPubPGPubProj,
		},
		{
			name:   "user member get pub org pub pg pub proj",
			client: gwClientUser02,
			proj:   pubOrgPubPGPubProj,
		},
		{
			name:   "user not member get pub org pub pg pub proj",
			client: gwClientUser03,
			proj:   pubOrgPubPGPubProj,
		},
		{
			name:   "user owner get pub org pub pg priv proj",
			client: gwClientUser01,
			proj:   pubOrgPubPGPrivProj,
		},
		{
			name:   "user member get pub org pub pg priv proj",
			client: gwClientUser02,
			proj:   pubOrgPubPGPrivProj,
		},
		{
			name:   "user not member get pub org pub pg priv proj",
			client: gwClientUser03,
			proj:   pubOrgPubPGPrivProj,
			err:    util.NewRemoteError(util.ErrNotExist, util.WithRemoteErrorDetailedError(&util.RemoteDetailedError{Code: gwapierrors.ErrorCodeOrganizationDoesNotExist})),
		},
		{
			name:   "user owner get pub org priv pg pub proj",
			client: gwClientUser01,
			proj:   pubOrgPrivPGPubProj,
		},
		{
			name:   "user member get pub org priv pg pub proj",
			client: gwClientUser02,
			proj:   pubOrgPrivPGPubProj,
		},
		{
			name:   "user not member get pub org priv pg pub proj",
			client: gwClientUser03,
			proj:   pubOrgPrivPGPubProj,
			err:    util.NewRemoteError(util.ErrNotExist, util.WithRemoteErrorDetailedError(&util.RemoteDetailedError{Code: gwapierrors.ErrorCodeOrganizationDoesNotExist})),
		},
		{
			name:   "user owner get pub org priv pg priv proj",
			client: gwClientUser01,
			proj:   pubOrgPrivPGPrivProj,
		},
		{
			name:   "user member get pub org priv pg priv proj",
			client: gwClientUser02,
			proj:   pubOrgPrivPGPrivProj,
		},
		{
			name:   "user not member get pub org priv pg priv proj",
			client: gwClientUser03,
			proj:   pubOrgPrivPGPrivProj,
			err:    util.NewRemoteError(util.ErrNotExist, util.WithRemoteErrorDetailedError(&util.RemoteDetailedError{Code: gwapierrors.ErrorCodeOrganizationDoesNotExist})),
		},
		{
			name:   "user owner get priv org pub pg pub proj",
			client: gwClientUser01,
			proj:   privOrgPubPGPubProj,
		},
		{
			name:   "user member get priv org pub pg pub proj",
			client: gwClientUser02,
			proj:   privOrgPubPGPubProj,
		},
		{
			name:   "user not member get priv org pub pg pub proj",
			client: gwClientUser03,
			proj:   privOrgPubPGPubProj,
			err:    util.NewRemoteError(util.ErrNotExist, util.WithRemoteErrorDetailedError(&util.RemoteDetailedError{Code: gwapierrors.ErrorCodeOrganizationDoesNotExist})),
		},
		{
			name:   "user owner get priv org pub pg priv proj",
			client: gwClientUser01,
			proj:   privOrgPubPGPrivProj,
		},
		{
			name:   "user member get priv org pub pg priv proj",
			client: gwClientUser02,
			proj:   privOrgPubPGPrivProj,
		},
		{
			name:   "user not member get priv org pub pg priv proj",
			client: gwClientUser03,
			proj:   privOrgPubPGPrivProj,
			err:    util.NewRemoteError(util.ErrNotExist, util.WithRemoteErrorDetailedError(&util.RemoteDetailedError{Code: gwapierrors.ErrorCodeOrganizationDoesNotExist})),
		},
		{
			name:   "user owner get priv org priv pg pub proj",
			client: gwClientUser01,
			proj:   privOrgPrivPGPubProj,
		},
		{
			name:   "user member get priv org priv pg pub proj",
			client: gwClientUser02,
			proj:   privOrgPrivPGPubProj,
		},
		{
			name:   "user not member get priv org priv pg pub proj",
			client: gwClientUser03,
			proj:   privOrgPrivPGPubProj,
			err:    util.NewRemoteError(util.ErrNotExist, util.WithRemoteErrorDetailedError(&util.RemoteDetailedError{Code: gwapierrors.ErrorCodeOrganizationDoesNotExist})),
		},
		{
			name:   "user owner get priv org priv pg priv proj",
			client: gwClientUser01,
			proj:   privOrgPrivPGPrivProj,
		},
		{
			name:   "user member get priv org priv pg priv proj",
			client: gwClientUser02,
			proj:   privOrgPrivPGPrivProj,
		},
		{
			name:   "user not member get priv org priv pg priv proj",
			client: gwClientUser03,
			proj:   privOrgPrivPGPrivProj,
			err:    util.NewRemoteError(util.ErrNotExist, util.WithRemoteErrorDetailedError(&util.RemoteDetailedError{Code: gwapierrors.ErrorCodeOrganizationDoesNotExist})),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			pg, _, err := tt.client.GetProject(ctx, tt.proj.ID)

			if tt.err != nil {
				assert.Error(t, err, tt.err.Error())
			} else {
				testutil.NilError(t, err)

				assert.DeepEqual(t, tt.proj, pg)
			}
		})
	}
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
	testutil.NilError(t, err)

	gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

	createProject(ctx, t, giteaClient, gwClient)
}

func TestUpdateProject(t *testing.T) {
	t.Parallel()

	t.Run("update PassVarsToForkedPR in users's project", func(t *testing.T) {
		dir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sc := setup(ctx, t, dir, withGitea(true))
		defer sc.stop()

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaToken, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		testutil.NilError(t, err)

		gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

		_, project := createProject(ctx, t, giteaClient, gwClient)
		assert.Assert(t, !project.PassVarsToForkedPR)

		project, _, err = gwClient.UpdateProject(ctx, project.ID, &gwapitypes.UpdateProjectRequest{
			PassVarsToForkedPR: util.Ptr(false),
		})
		testutil.NilError(t, err)

		assert.Assert(t, !project.PassVarsToForkedPR)

		project, _, err = gwClient.UpdateProject(ctx, project.ID, &gwapitypes.UpdateProjectRequest{
			PassVarsToForkedPR: util.Ptr(true),
		})
		testutil.NilError(t, err)

		assert.Assert(t, project.PassVarsToForkedPR)
	})

	t.Run("create users's project with MembersCanPerformRunActions true", func(t *testing.T) {
		dir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sc := setup(ctx, t, dir, withGitea(true))
		defer sc.stop()

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaToken, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		testutil.NilError(t, err)

		gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

		giteaRepo, _, err := giteaClient.CreateRepo(gitea.CreateRepoOption{
			Name:    "repo01",
			Private: false,
		})
		testutil.NilError(t, err)

		t.Logf("created gitea repo: %s", giteaRepo.Name)

		req := &gwapitypes.CreateProjectRequest{
			Name:                        "project01",
			RemoteSourceName:            "gitea",
			RepoPath:                    path.Join(giteaUser01, "repo01"),
			Visibility:                  gwapitypes.VisibilityPublic,
			MembersCanPerformRunActions: true,
		}

		_, _, err = gwClient.CreateProject(ctx, req)
		expectedErr := util.NewRemoteError(util.ErrBadRequest, util.WithRemoteErrorDetailedError(&util.RemoteDetailedError{Code: gwapierrors.ErrorCodeCannotSetMembersCanPerformRunActionsOnUserProject}))
		assert.Error(t, err, expectedErr.Error())
	})

	t.Run("update users's project with MembersCanPerformRunActions true", func(t *testing.T) {
		dir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sc := setup(ctx, t, dir, withGitea(true))
		defer sc.stop()

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaToken, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		testutil.NilError(t, err)

		gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

		_, project := createProject(ctx, t, giteaClient, gwClient)
		assert.Assert(t, !project.MembersCanPerformRunActions)

		_, _, err = gwClient.UpdateProject(ctx, project.ID, &gwapitypes.UpdateProjectRequest{
			Name:                        &project.Name,
			MembersCanPerformRunActions: util.Ptr(true),
		})
		expectedErr := util.NewRemoteError(util.ErrBadRequest, util.WithRemoteErrorDetailedError(&util.RemoteDetailedError{Code: gwapierrors.ErrorCodeCannotSetMembersCanPerformRunActionsOnUserProject}))
		assert.Error(t, err, expectedErr.Error())
	})

	t.Run("create/update orgs's project", func(t *testing.T) {
		dir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sc := setup(ctx, t, dir, withGitea(true))
		defer sc.stop()

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaToken, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		testutil.NilError(t, err)

		gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

		_, _, err = gwClient.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
		testutil.NilError(t, err)

		// test create org project with MembersCanPerformRunActions false
		_, project := createProject(ctx, t, giteaClient, gwClient, withParentRef(path.Join("org", agolaOrg01)))
		assert.Assert(t, !project.MembersCanPerformRunActions)

		// test update org project with MembersCanPerformRunActions true
		project, _, err = gwClient.UpdateProject(ctx, project.ID, &gwapitypes.UpdateProjectRequest{
			Name:                        &project.Name,
			MembersCanPerformRunActions: util.Ptr(true),
		})
		testutil.NilError(t, err)

		assert.Assert(t, project.MembersCanPerformRunActions)

		// test create org project with MembersCanPerformRunActions true
		project, _, err = gwClient.CreateProject(ctx, &gwapitypes.CreateProjectRequest{
			Name:                        "project02",
			RemoteSourceName:            "gitea",
			RepoPath:                    path.Join(giteaUser01, "repo01"),
			Visibility:                  gwapitypes.VisibilityPublic,
			ParentRef:                   path.Join("org", agolaOrg01),
			MembersCanPerformRunActions: true,
		})
		testutil.NilError(t, err)

		assert.Assert(t, project.MembersCanPerformRunActions)

		// test update org project with MembersCanPerformRunActions false
		project, _, err = gwClient.UpdateProject(ctx, project.ID, &gwapitypes.UpdateProjectRequest{
			Name:                        &project.Name,
			MembersCanPerformRunActions: util.Ptr(false),
		})
		testutil.NilError(t, err)

		assert.Assert(t, !project.MembersCanPerformRunActions)
	})
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
	testutil.NilError(t, err)

	gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

	giteaRepo, project := createProject(ctx, t, giteaClient, gwClient)

	assert.Equal(t, project.DefaultBranch, "master")

	_, _, err = giteaClient.EditRepo(giteaRepo.Owner.UserName, giteaRepo.Name, gitea.EditRepoOption{DefaultBranch: util.Ptr("testbranch")})
	testutil.NilError(t, err)

	project, _, err = gwClient.RefreshRemoteRepo(ctx, project.ID)
	testutil.NilError(t, err)

	assert.Equal(t, project.DefaultBranch, "testbranch")

	p, _, err := gwClient.GetProject(ctx, project.ID)
	testutil.NilError(t, err)

	assert.DeepEqual(t, project, p)
}

func TestGetProjectRun(t *testing.T) {
	t.Parallel()

	t.Run("get not existing run", func(t *testing.T) {
		dir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sc := setup(ctx, t, dir, withGitea(true))
		defer sc.stop()

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaToken, token := createLinkedAccount(ctx, t, sc.gitea, sc.config)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		testutil.NilError(t, err)

		gwClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token)

		_, project := createProject(ctx, t, giteaClient, gwClient)

		_, _, err = gwClient.GetProjectRun(ctx, project.ID, 1)
		expectedErr := util.NewRemoteError(util.ErrNotExist, util.WithRemoteErrorDetailedError(&util.RemoteDetailedError{Code: gwapierrors.ErrorCodeRunDoesNotExist}))
		assert.Error(t, err, expectedErr.Error())
	})
}

func TestProjectRunActions(t *testing.T) {
	t.Parallel()

	config := EnvRunConfig

	expectedErr := remoteErrorForbidden

	t.Run("run actions on org's project", func(t *testing.T) {
		dir := t.TempDir()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sc := setup(ctx, t, dir, withGitea(true))
		defer sc.stop()

		giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		testutil.NilError(t, err)

		gwAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)
		gwUser01Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)

		_, _, err = gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
		testutil.NilError(t, err)

		token, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser02, &gwapitypes.CreateUserTokenRequest{TokenName: "testtoken"})
		testutil.NilError(t, err)

		gwUser02Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token.Token)

		_, _, err = gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser03})
		testutil.NilError(t, err)

		token, _, err = gwAdminClient.CreateUserToken(ctx, agolaUser03, &gwapitypes.CreateUserTokenRequest{TokenName: "testtoken"})
		testutil.NilError(t, err)

		gwUser03Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token.Token)

		_, _, err = gwUser01Client.CreateOrg(ctx, &gwapitypes.CreateOrgRequest{Name: agolaOrg01, Visibility: gwapitypes.VisibilityPublic})
		testutil.NilError(t, err)

		_, _, err = gwUser01Client.AddOrgMember(ctx, agolaOrg01, agolaUser02, gwapitypes.MemberRoleMember)
		testutil.NilError(t, err)

		giteaRepo, project := createProject(ctx, t, giteaClient, gwUser01Client, withParentRef(path.Join("org", agolaOrg01)), withMembersCanPerformRunActions(true))

		push(t, config, giteaRepo.CloneURL, giteaToken, "commit", false)

		// test org run actions executed by an user that's organization owner

		err = testutil.Wait(60*time.Second, func() (bool, error) {
			runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, &gwclient.GetRunsOptions{ListOptions: &gwclient.ListOptions{SortDirection: gwapitypes.SortDirectionDesc}})
			if err != nil {
				return false, nil
			}

			if len(runs) == 0 {
				return false, nil
			}
			if runs[0].Phase != rstypes.RunPhaseFinished {
				return false, nil
			}

			return true, nil
		})
		testutil.NilError(t, err)

		runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, &gwclient.GetRunsOptions{ListOptions: &gwclient.ListOptions{SortDirection: gwapitypes.SortDirectionDesc}})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(runs, 1))

		assert.Equal(t, runs[0].Phase, rstypes.RunPhaseFinished)
		assert.Equal(t, runs[0].Result, rstypes.RunResultSuccess)

		_, _, err = gwUser01Client.ProjectRunAction(ctx, project.ID, runs[0].Number, &gwapitypes.RunActionsRequest{
			ActionType: gwapitypes.RunActionTypeRestart,
			FromStart:  true,
		})
		testutil.NilError(t, err)

		// test org run actions executed by an organization member type with project MembersCanPerformRunActions set to true

		_, _, err = gwUser02Client.ProjectRunAction(ctx, project.ID, runs[0].Number, &gwapitypes.RunActionsRequest{
			ActionType: gwapitypes.RunActionTypeRestart,
			FromStart:  true,
		})
		testutil.NilError(t, err)

		// test org run actions executed by an user that isn't organization member

		_, _, err = gwUser03Client.ProjectRunAction(ctx, project.ID, runs[0].Number, &gwapitypes.RunActionsRequest{
			ActionType: gwapitypes.RunActionTypeRestart,
			FromStart:  true,
		})
		assert.Error(t, err, expectedErr.Error())

		// test org run actions executed by an organization member type with MembersCanPerformRunActions false

		_, _, err = gwUser01Client.UpdateProject(ctx, project.ID, &gwapitypes.UpdateProjectRequest{
			MembersCanPerformRunActions: util.Ptr(false),
		})
		testutil.NilError(t, err)

		_, _, err = gwUser02Client.ProjectRunAction(ctx, project.ID, runs[0].Number, &gwapitypes.RunActionsRequest{
			ActionType: gwapitypes.RunActionTypeRestart,
			FromStart:  true,
		})
		assert.Error(t, err, expectedErr.Error())
	})

	t.Run("run actions on user's project", func(t *testing.T) {
		dir := t.TempDir()

		// for user project MembersCanPerformRunActions will be ignored

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sc := setup(ctx, t, dir, withGitea(true))
		defer sc.stop()

		giteaToken, tokenUser01 := createLinkedAccount(ctx, t, sc.gitea, sc.config)

		gwAdminClient := gwclient.NewClient(sc.config.Gateway.APIExposedURL, sc.config.Gateway.AdminToken)
		gwUser01Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, tokenUser01)

		_, _, err := gwAdminClient.CreateUser(ctx, &gwapitypes.CreateUserRequest{UserName: agolaUser02})
		testutil.NilError(t, err)

		token, _, err := gwAdminClient.CreateUserToken(ctx, agolaUser02, &gwapitypes.CreateUserTokenRequest{TokenName: "testtoken"})
		testutil.NilError(t, err)

		gwUser02Client := gwclient.NewClient(sc.config.Gateway.APIExposedURL, token.Token)

		giteaAPIURL := fmt.Sprintf("http://%s:%s", sc.gitea.HTTPListenAddress, sc.gitea.HTTPPort)

		giteaClient, err := gitea.NewClient(giteaAPIURL, gitea.SetToken(giteaToken))
		testutil.NilError(t, err)

		giteaRepo, project := createProject(ctx, t, giteaClient, gwUser01Client)

		push(t, config, giteaRepo.CloneURL, giteaToken, "commit", false)

		err = testutil.Wait(60*time.Second, func() (bool, error) {
			runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, &gwclient.GetRunsOptions{ListOptions: &gwclient.ListOptions{SortDirection: gwapitypes.SortDirectionDesc}})
			if err != nil {
				return false, nil
			}

			if len(runs) == 0 {
				return false, nil
			}
			if runs[0].Phase != rstypes.RunPhaseFinished {
				return false, nil
			}

			return true, nil
		})
		testutil.NilError(t, err)

		runs, _, err := gwUser01Client.GetProjectRuns(ctx, project.ID, &gwclient.GetRunsOptions{ListOptions: &gwclient.ListOptions{SortDirection: gwapitypes.SortDirectionDesc}})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(runs, 1))

		assert.Equal(t, runs[0].Phase, rstypes.RunPhaseFinished)
		assert.Equal(t, runs[0].Result, rstypes.RunResultSuccess)

		_, _, err = gwUser01Client.ProjectRunAction(ctx, project.ID, runs[0].Number, &gwapitypes.RunActionsRequest{
			ActionType: gwapitypes.RunActionTypeRestart,
			FromStart:  true,
		})
		testutil.NilError(t, err)

		// test user run actions unauthorized

		_, _, err = gwUser02Client.ProjectRunAction(ctx, project.ID, runs[0].Number, &gwapitypes.RunActionsRequest{
			ActionType: gwapitypes.RunActionTypeRestart,
			FromStart:  true,
		})
		assert.Error(t, err, expectedErr.Error())
	})
}
