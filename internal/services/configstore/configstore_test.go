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

package configstore

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/sqlg"
	"agola.io/agola/internal/sqlg/sql"
	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"
)

func setupConfigstore(ctx context.Context, t *testing.T, log zerolog.Logger, dir string) *Configstore {
	port, err := testutil.GetFreePort("localhost", true, false)
	testutil.NilError(t, err)

	ostDir, err := os.MkdirTemp(dir, "ost")
	testutil.NilError(t, err)

	csDir, err := os.MkdirTemp(dir, "cs")
	testutil.NilError(t, err)

	dbType := testutil.DBType(t)
	_, _, dbConnString := testutil.CreateDB(t, log, ctx, dir)

	baseConfig := config.Configstore{
		DB: config.DB{
			Type:       dbType,
			ConnString: dbConnString,
		},
		ObjectStorage: config.ObjectStorage{
			Type: config.ObjectStorageTypePosix,
			Path: ostDir,
		},
		Web: config.Web{},
	}
	csConfig := baseConfig
	csConfig.DataDir = csDir
	csConfig.Web.ListenAddress = net.JoinHostPort("localhost", port)

	cs, err := NewConfigstore(ctx, log, &csConfig)
	testutil.NilError(t, err)

	return cs
}

func getRemoteSources(ctx context.Context, cs *Configstore) ([]*types.RemoteSource, error) {
	var users []*types.RemoteSource
	err := cs.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		users, err = cs.d.GetRemoteSources(tx, "", 0, types.SortDirectionAsc)
		return errors.WithStack(err)
	})

	return users, errors.WithStack(err)
}
func getUsers(ctx context.Context, cs *Configstore) ([]*types.User, error) {
	var users []*types.User
	err := cs.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		users, err = cs.d.GetUsers(tx, "", 0, types.SortDirectionAsc)
		return errors.WithStack(err)
	})

	return users, errors.WithStack(err)
}

func getOrgs(ctx context.Context, cs *Configstore) ([]*types.Organization, error) {
	var orgs []*types.Organization
	err := cs.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		orgs, err = cs.d.GetOrgs(tx, "", nil, 0, types.SortDirectionAsc)
		return errors.WithStack(err)
	})

	return orgs, errors.WithStack(err)
}

func getProjectGroups(ctx context.Context, cs *Configstore) ([]*types.ProjectGroup, error) {
	var projectGroups []*types.ProjectGroup
	err := cs.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		projectGroups, err = cs.d.GetAllProjectGroups(tx)
		return errors.WithStack(err)
	})

	return projectGroups, errors.WithStack(err)
}

func getProjects(ctx context.Context, cs *Configstore) ([]*types.Project, error) {
	var projects []*types.Project
	err := cs.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		projects, err = cs.d.GetAllProjects(tx)
		return errors.WithStack(err)
	})

	return projects, errors.WithStack(err)
}

func getSecrets(ctx context.Context, cs *Configstore) ([]*types.Secret, error) {
	var secrets []*types.Secret
	err := cs.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		secrets, err = cs.d.GetAllSecrets(tx)
		return errors.WithStack(err)
	})

	return secrets, errors.WithStack(err)
}

func getVariables(ctx context.Context, cs *Configstore) ([]*types.Variable, error) {
	var variables []*types.Variable
	err := cs.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		variables, err = cs.d.GetAllVariables(tx)
		return errors.WithStack(err)
	})

	return variables, errors.WithStack(err)
}

func cmpDiffObject(x, y interface{}) cmp.Comparison {
	// Since postgres has microsecond time precision while go has nanosecond time precision we should check times with a microsecond margin
	return cmp.DeepEqual(x, y, cmpopts.IgnoreFields(sqlg.ObjectMeta{}, "TxID"), cmpopts.EquateApproxTime(1*time.Microsecond))
}

func TestExportImport(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	cs := setupConfigstore(ctx, t, log, dir)

	t.Logf("starting cs")
	go func() { _ = cs.Run(ctx) }()

	var expectedRemoteSourcesCount int
	var expectedUsersCount int
	var expectedOrgsCount int
	var expectedProjectGroupsCount int
	var expectedProjectsCount int
	var expectedSecretsCount int
	var expectedVariablesCount int

	_, err := cs.ah.CreateRemoteSource(ctx, &action.CreateUpdateRemoteSourceRequest{Name: "rs01", Type: types.RemoteSourceTypeGitea, AuthType: types.RemoteSourceAuthTypePassword, APIURL: "http://example.com"})
	testutil.NilError(t, err)

	expectedRemoteSourcesCount++

	for i := 0; i < 20; i++ {
		_, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: fmt.Sprintf("user%d", i)})
		testutil.NilError(t, err)

		expectedUsersCount++
		expectedProjectGroupsCount++
	}

	user, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
	testutil.NilError(t, err)

	expectedUsersCount++
	expectedProjectGroupsCount++

	org, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: "org01", Visibility: types.VisibilityPublic})
	testutil.NilError(t, err)

	expectedOrgsCount++
	expectedProjectGroupsCount++

	_, err = cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
	testutil.NilError(t, err)

	expectedProjectsCount++

	_, err = cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic})
	testutil.NilError(t, err)

	expectedProjectGroupsCount++

	_, err = cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
	testutil.NilError(t, err)

	expectedProjectsCount++

	_, err = cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic})
	testutil.NilError(t, err)

	expectedProjectGroupsCount++

	_, err = cs.ah.CreateSecret(ctx, &action.CreateUpdateSecretRequest{Name: "secret01", Parent: types.Parent{Kind: types.ObjectKindProject, ID: path.Join("user", user.Name, "projectgroup01", "project01")}, Type: types.SecretTypeInternal, Data: map[string]string{"secret01": "secretvar01"}})
	testutil.NilError(t, err)

	expectedSecretsCount++

	_, err = cs.ah.CreateVariable(ctx, &action.CreateUpdateVariableRequest{Name: "variable01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Values: []types.VariableValue{{SecretName: "secret01", SecretVar: "secretvar01"}}})
	testutil.NilError(t, err)

	expectedVariablesCount++

	remoteSources, err := getRemoteSources(ctx, cs)
	testutil.NilError(t, err)

	users, err := getUsers(ctx, cs)
	testutil.NilError(t, err)

	orgs, err := getOrgs(ctx, cs)
	testutil.NilError(t, err)

	projectGroups, err := getProjectGroups(ctx, cs)
	testutil.NilError(t, err)

	projects, err := getProjects(ctx, cs)
	testutil.NilError(t, err)

	secrets, err := getSecrets(ctx, cs)
	testutil.NilError(t, err)

	variables, err := getVariables(ctx, cs)
	testutil.NilError(t, err)

	assert.Assert(t, cmp.Len(remoteSources, expectedRemoteSourcesCount))
	assert.Assert(t, cmp.Len(users, expectedUsersCount))
	assert.Assert(t, cmp.Len(orgs, expectedOrgsCount))
	assert.Assert(t, cmp.Len(projectGroups, expectedProjectGroupsCount))
	assert.Assert(t, cmp.Len(projects, expectedProjectsCount))
	assert.Assert(t, cmp.Len(secrets, expectedSecretsCount))
	assert.Assert(t, cmp.Len(variables, expectedVariablesCount))

	var export bytes.Buffer
	err = cs.ah.Export(ctx, &export)
	testutil.NilError(t, err)

	err = cs.ah.SetMaintenanceEnabled(ctx, true)
	testutil.NilError(t, err)

	_ = testutil.Wait(30*time.Second, func() (bool, error) {
		if !cs.ah.IsMaintenanceMode() {
			return false, nil
		}

		return true, nil
	})

	err = cs.ah.Import(ctx, &export)
	testutil.NilError(t, err)

	err = cs.ah.SetMaintenanceEnabled(ctx, false)
	testutil.NilError(t, err)

	_ = testutil.Wait(30*time.Second, func() (bool, error) {
		if cs.ah.IsMaintenanceMode() {
			return false, nil
		}

		return true, nil
	})

	newRemoteSources, err := getRemoteSources(ctx, cs)
	testutil.NilError(t, err)

	newUsers, err := getUsers(ctx, cs)
	testutil.NilError(t, err)

	newOrgs, err := getOrgs(ctx, cs)
	testutil.NilError(t, err)

	newProjectGroups, err := getProjectGroups(ctx, cs)
	testutil.NilError(t, err)

	newProjects, err := getProjects(ctx, cs)
	testutil.NilError(t, err)

	newSecrets, err := getSecrets(ctx, cs)
	testutil.NilError(t, err)

	newVariables, err := getVariables(ctx, cs)
	testutil.NilError(t, err)

	assert.Assert(t, cmpDiffObject(remoteSources, newRemoteSources))
	assert.Assert(t, cmpDiffObject(users, newUsers))
	assert.Assert(t, cmpDiffObject(orgs, newOrgs))
	assert.Assert(t, cmpDiffObject(projectGroups, newProjectGroups))
	assert.Assert(t, cmpDiffObject(projects, newProjects))
	assert.Assert(t, cmpDiffObject(secrets, newSecrets))
	assert.Assert(t, cmpDiffObject(variables, newVariables))
}

func TestUser(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	cs := setupConfigstore(ctx, t, log, dir)

	t.Logf("starting cs")
	go func() {
		_ = cs.Run(ctx)
	}()

	t.Run("create user", func(t *testing.T) {
		_, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
		testutil.NilError(t, err)
	})

	t.Run("create duplicated user", func(t *testing.T) {
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("user with name %q already exists", "user01"))
		_, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
		assert.Error(t, err, expectedErr.Error())
	})
	t.Run("concurrent user with same name creation", func(t *testing.T) {
		prevUsers, err := getUsers(ctx, cs)
		testutil.NilError(t, err)

		wg := sync.WaitGroup{}
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				_, _ = cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user02"})
				wg.Done()
			}()
		}
		wg.Wait()

		users, err := getUsers(ctx, cs)
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(users, len(prevUsers)+1))
	})

	t.Run("delete user", func(t *testing.T) {
		_, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user03"})
		testutil.NilError(t, err)

		err = cs.ah.DeleteUser(ctx, "user03")
		testutil.NilError(t, err)

		var user *types.User
		err = cs.d.Do(ctx, func(tx *sql.Tx) error {
			var err error
			user, err = cs.d.GetUser(tx, "user03")
			return errors.WithStack(err)
		})
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Nil(user))
	})
}

func TestProjectGroupsAndProjectsCreate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	cs := setupConfigstore(ctx, t, log, dir)

	t.Logf("starting cs")
	go func() {
		_ = cs.Run(ctx)
	}()

	user, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
	testutil.NilError(t, err)

	org, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: "org01", Visibility: types.VisibilityPublic})
	testutil.NilError(t, err)

	t.Run("create a project in user root project group", func(t *testing.T) {
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		testutil.NilError(t, err)
	})
	t.Run("create a project in org root project group", func(t *testing.T) {
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		testutil.NilError(t, err)
	})
	t.Run("create a projectgroup in user root project group", func(t *testing.T) {
		_, err := cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic})
		testutil.NilError(t, err)
	})
	t.Run("create a projectgroup in org root project group", func(t *testing.T) {
		_, err := cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic})
		testutil.NilError(t, err)
	})
	t.Run("create a project in user non root project group with same name as a root project", func(t *testing.T) {
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		testutil.NilError(t, err)
	})
	t.Run("create a project in org non root project group with same name as a root project", func(t *testing.T) {
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		testutil.NilError(t, err)
	})

	t.Run("create duplicated project in user root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with name %q, path %q already exists", projectName, path.Join("user", user.Name, projectName)))
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: projectName, Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		assert.Error(t, err, expectedErr.Error())
	})
	t.Run("create duplicated project in org root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with name %q, path %q already exists", projectName, path.Join("org", org.Name, projectName)))
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: projectName, Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		assert.Error(t, err, expectedErr.Error())
	})

	t.Run("create duplicated project in user non root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with name %q, path %q already exists", projectName, path.Join("user", user.Name, "projectgroup01", projectName)))
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: projectName, Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		assert.Error(t, err, expectedErr.Error())
	})
	t.Run("create duplicated project in org non root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with name %q, path %q already exists", projectName, path.Join("org", org.Name, "projectgroup01", projectName)))
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: projectName, Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		assert.Error(t, err, expectedErr.Error())
	})

	t.Run("create project in unexistent project group", func(t *testing.T) {
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf(`project group with id "unexistentid" doesn't exist`))
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: "unexistentid"}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		assert.Error(t, err, expectedErr.Error())
	})
	t.Run("create project without parent id specified", func(t *testing.T) {
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project parent id required"))
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		assert.Error(t, err, expectedErr.Error())
	})

	t.Run("concurrent project with same name creation", func(t *testing.T) {
		prevProjects, err := getProjects(ctx, cs)
		testutil.NilError(t, err)

		wg := sync.WaitGroup{}
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				_, _ = cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project02", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
				wg.Done()
			}()
		}
		wg.Wait()

		projects, err := getProjects(ctx, cs)
		testutil.NilError(t, err)

		assert.Assert(t, cmp.Len(projects, len(prevProjects)+1))
	})
}

func TestProjectUpdate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	cs := setupConfigstore(ctx, t, log, dir)

	t.Logf("starting cs")
	go func() {
		_ = cs.Run(ctx)
	}()

	user, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
	testutil.NilError(t, err)

	_, err = cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic})
	testutil.NilError(t, err)

	p01 := &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual}
	_, err = cs.ah.CreateProject(ctx, p01)
	testutil.NilError(t, err)

	p02 := &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual}
	_, err = cs.ah.CreateProject(ctx, p02)
	testutil.NilError(t, err)

	p03 := &action.CreateUpdateProjectRequest{Name: "project02", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual}
	_, err = cs.ah.CreateProject(ctx, p03)
	testutil.NilError(t, err)

	t.Run("rename project keeping same parent", func(t *testing.T) {
		projectName := "project02"
		p03.Name = "newproject02"
		_, err := cs.ah.UpdateProject(ctx, path.Join("user", user.Name, "projectgroup01", projectName), p03)
		testutil.NilError(t, err)
	})
	t.Run("move project to project group having project with same name", func(t *testing.T) {
		projectName := "project01"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with name %q, path %q already exists", projectName, path.Join("user", user.Name, projectName)))
		p02.Parent.ID = path.Join("user", user.Name)
		_, err := cs.ah.UpdateProject(ctx, path.Join("user", user.Name, "projectgroup01", projectName), p02)
		assert.Error(t, err, expectedErr.Error())
	})
	t.Run("move project to project group changing name", func(t *testing.T) {
		projectName := "project01"
		p02.Name = "newproject01"
		p02.Parent.ID = path.Join("user", user.Name)
		_, err := cs.ah.UpdateProject(ctx, path.Join("user", user.Name, "projectgroup01", projectName), p02)
		testutil.NilError(t, err)
	})
	t.Run("test user project MembersCanPerformRunActions parameter", func(t *testing.T) {
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot set MembersCanPerformRunActions on an user project."))
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{
			Name:                        "project03",
			Parent:                      types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)},
			Visibility:                  types.VisibilityPublic,
			RemoteRepositoryConfigType:  types.RemoteRepositoryConfigTypeManual,
			MembersCanPerformRunActions: true,
		})
		assert.Error(t, err, expectedErr.Error())

		// test update user project

		p01.MembersCanPerformRunActions = true
		_, err = cs.ah.UpdateProject(ctx, path.Join("user", user.Name, "project01"), p01)
		assert.Error(t, err, expectedErr.Error())
	})
}

func TestProjectGroupUpdate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	cs := setupConfigstore(ctx, t, log, dir)

	t.Logf("starting cs")
	go func() {
		_ = cs.Run(ctx)
	}()

	user, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
	testutil.NilError(t, err)

	rootPG, err := cs.ah.GetProjectGroup(ctx, path.Join("user", user.Name))
	testutil.NilError(t, err)

	pg01req := &action.CreateUpdateProjectGroupRequest{Name: "pg01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic}
	_, err = cs.ah.CreateProjectGroup(ctx, pg01req)
	testutil.NilError(t, err)

	pg02req := &action.CreateUpdateProjectGroupRequest{Name: "pg02", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic}
	_, err = cs.ah.CreateProjectGroup(ctx, pg02req)
	testutil.NilError(t, err)

	pg03req := &action.CreateUpdateProjectGroupRequest{Name: "pg03", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic}
	_, err = cs.ah.CreateProjectGroup(ctx, pg03req)
	testutil.NilError(t, err)

	pg04req := &action.CreateUpdateProjectGroupRequest{Name: "pg01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "pg01")}, Visibility: types.VisibilityPublic}
	_, err = cs.ah.CreateProjectGroup(ctx, pg04req)
	testutil.NilError(t, err)

	pg05req := &action.CreateUpdateProjectGroupRequest{Name: "pg01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "pg02")}, Visibility: types.VisibilityPublic}
	_, err = cs.ah.CreateProjectGroup(ctx, pg05req)
	testutil.NilError(t, err)

	t.Run("rename project group keeping same parent", func(t *testing.T) {
		projectGroupName := "pg03"
		pg03req.Name = "newpg03"
		_, err := cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name, projectGroupName), pg03req)
		testutil.NilError(t, err)
	})
	t.Run("move project to project group having project with same name", func(t *testing.T) {
		projectGroupName := "pg01"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group with name %q, path %q already exists", projectGroupName, path.Join("user", user.Name, projectGroupName)))
		pg05req.Parent.ID = path.Join("user", user.Name)
		_, err := cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name, "pg02", projectGroupName), pg05req)
		assert.Error(t, err, expectedErr.Error())
	})
	t.Run("move project group to root project group changing name", func(t *testing.T) {
		projectGroupName := "pg01"
		pg05req.Name = "newpg01"
		pg05req.Parent.ID = path.Join("user", user.Name)
		pg05, err := cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name, "pg02", projectGroupName), pg05req)
		testutil.NilError(t, err)

		assert.Equal(t, pg05.Parent.ID, rootPG.ID)
	})
	t.Run("move project group inside itself", func(t *testing.T) {
		projectGroupName := "pg02"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot move project group inside itself or child project group"))
		pg02req.Parent.ID = path.Join("user", user.Name, "pg02")
		_, err := cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name, projectGroupName), pg02req)
		assert.Error(t, err, expectedErr.Error())
	})
	t.Run("move project group to child project group", func(t *testing.T) {
		projectGroupName := "pg01"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot move project group inside itself or child project group"))
		pg01req.Parent.ID = path.Join("user", user.Name, "pg01", "pg01")
		_, err := cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name, projectGroupName), pg01req)
		assert.Error(t, err, expectedErr.Error())
	})
	t.Run("change root project group parent kind", func(t *testing.T) {
		var rootPG *types.ProjectGroup
		rootPG, err := cs.ah.GetProjectGroup(ctx, path.Join("user", user.Name))
		testutil.NilError(t, err)

		rootPG.Parent.Kind = types.ObjectKindProjectGroup
		rootPG.Name = "rootpg"

		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("changing project group parent kind isn't supported"))
		_, err = cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name), &action.CreateUpdateProjectGroupRequest{Name: rootPG.Name, Parent: rootPG.Parent, Visibility: rootPG.Visibility})
		assert.Error(t, err, expectedErr.Error())
	})
	t.Run("change root project group parent id", func(t *testing.T) {
		var rootPG *types.ProjectGroup
		rootPG, err := cs.ah.GetProjectGroup(ctx, path.Join("user", user.Name))
		testutil.NilError(t, err)

		rootPG.Parent.ID = path.Join("user", user.Name, "pg01")

		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot change root project group parent kind or id"))
		_, err = cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name), &action.CreateUpdateProjectGroupRequest{Name: rootPG.Name, Parent: rootPG.Parent, Visibility: rootPG.Visibility})
		assert.Error(t, err, expectedErr.Error())
	})
	t.Run("change root project group name", func(t *testing.T) {
		var rootPG *types.ProjectGroup
		rootPG, err := cs.ah.GetProjectGroup(ctx, path.Join("user", user.Name))
		testutil.NilError(t, err)

		rootPG.Name = "rootpgnewname"

		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group name for root project group must be empty"))
		_, err = cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name), &action.CreateUpdateProjectGroupRequest{Name: rootPG.Name, Parent: rootPG.Parent, Visibility: rootPG.Visibility})
		assert.Error(t, err, expectedErr.Error())
	})
	t.Run("change root project group visibility", func(t *testing.T) {
		var rootPG *types.ProjectGroup
		rootPG, err := cs.ah.GetProjectGroup(ctx, path.Join("user", user.Name))
		testutil.NilError(t, err)

		rootPG.Visibility = types.VisibilityPrivate

		_, err = cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name), &action.CreateUpdateProjectGroupRequest{Name: rootPG.Name, Parent: rootPG.Parent, Visibility: rootPG.Visibility})
		testutil.NilError(t, err)

		rootPG, err = cs.ah.GetProjectGroup(ctx, path.Join("user", user.Name))
		testutil.NilError(t, err)

		assert.Equal(t, rootPG.Visibility, types.VisibilityPrivate)
	})
}

func TestProjectGroupDelete(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	cs := setupConfigstore(ctx, t, log, dir)

	t.Logf("starting cs")
	go func() {
		_ = cs.Run(ctx)
	}()

	org, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: "org01", Visibility: types.VisibilityPublic})
	testutil.NilError(t, err)

	// create a projectgroup in org root project group
	pg01, err := cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic})
	testutil.NilError(t, err)

	// create a child projectgroup in org root project group
	_, err = cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "subprojectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: pg01.ID}, Visibility: types.VisibilityPublic})
	testutil.NilError(t, err)

	t.Run("delete root project group", func(t *testing.T) {
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot delete root project group"))
		err := cs.ah.DeleteProjectGroup(ctx, path.Join("org", org.Name))
		assert.Error(t, err, expectedErr.Error())
	})

	t.Run("delete project group", func(t *testing.T) {
		err := cs.ah.DeleteProjectGroup(ctx, pg01.ID)
		testutil.NilError(t, err)
	})
}

func TestProjectGroupDeleteDontSeeOldChildObjects(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	cs := setupConfigstore(ctx, t, log, dir)

	t.Logf("starting cs")
	go func() {
		_ = cs.Run(ctx)
	}()

	org, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: "org01", Visibility: types.VisibilityPublic})
	testutil.NilError(t, err)

	// create a projectgroup in org root project group
	pg01, err := cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic})
	testutil.NilError(t, err)

	// create a child projectgroup in org root project group
	spg01, err := cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "subprojectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: pg01.ID}, Visibility: types.VisibilityPublic})
	testutil.NilError(t, err)

	// create a project inside child projectgroup
	project, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: spg01.ID}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
	testutil.NilError(t, err)

	// create project secret
	_, err = cs.ah.CreateSecret(ctx, &action.CreateUpdateSecretRequest{Name: "secret01", Parent: types.Parent{Kind: types.ObjectKindProject, ID: project.ID}, Type: types.SecretTypeInternal, Data: map[string]string{"secret01": "secretvar01"}})
	testutil.NilError(t, err)

	// create project variable
	_, err = cs.ah.CreateVariable(ctx, &action.CreateUpdateVariableRequest{Name: "variable01", Parent: types.Parent{Kind: types.ObjectKindProject, ID: project.ID}, Values: []types.VariableValue{{SecretName: "secret01", SecretVar: "secretvar01"}}})
	testutil.NilError(t, err)

	// delete projectgroup
	err = cs.ah.DeleteProjectGroup(ctx, pg01.ID)
	testutil.NilError(t, err)

	// recreate the same hierarchj using the paths
	pg01, err = cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic})
	testutil.NilError(t, err)

	spg01, err = cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "subprojectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name, pg01.Name)}, Visibility: types.VisibilityPublic})
	testutil.NilError(t, err)

	project, err = cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name, pg01.Name, spg01.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
	testutil.NilError(t, err)

	secret, err := cs.ah.CreateSecret(ctx, &action.CreateUpdateSecretRequest{Name: "secret01", Parent: types.Parent{Kind: types.ObjectKindProject, ID: path.Join("org", org.Name, pg01.Name, spg01.Name, project.Name)}, Type: types.SecretTypeInternal, Data: map[string]string{"secret01": "secretvar01"}})
	testutil.NilError(t, err)

	variable, err := cs.ah.CreateVariable(ctx, &action.CreateUpdateVariableRequest{Name: "variable01", Parent: types.Parent{Kind: types.ObjectKindProject, ID: path.Join("org", org.Name, pg01.Name, spg01.Name, project.Name)}, Values: []types.VariableValue{{SecretName: "secret01", SecretVar: "secretvar01"}}})
	testutil.NilError(t, err)

	// Get by projectgroup id
	projects, err := cs.ah.GetProjectGroupProjects(ctx, spg01.ID)
	testutil.NilError(t, err)

	assert.Assert(t, cmpDiffObject(projects, []*types.Project{project}))

	// Get by projectgroup path
	projects, err = cs.ah.GetProjectGroupProjects(ctx, path.Join("org", org.Name, pg01.Name, spg01.Name))
	testutil.NilError(t, err)

	assert.Assert(t, cmpDiffObject(projects, []*types.Project{project}))

	secrets, err := cs.ah.GetSecrets(ctx, types.ObjectKindProject, project.ID, false)
	testutil.NilError(t, err)

	assert.Assert(t, cmpDiffObject(secrets, []*types.Secret{secret}))

	secrets, err = cs.ah.GetSecrets(ctx, types.ObjectKindProject, path.Join("org", org.Name, pg01.Name, spg01.Name, project.Name), false)
	testutil.NilError(t, err)

	assert.Assert(t, cmpDiffObject(secrets, []*types.Secret{secret}))

	variables, err := cs.ah.GetVariables(ctx, types.ObjectKindProject, project.ID, false)
	testutil.NilError(t, err)

	assert.Assert(t, cmpDiffObject(variables, []*types.Variable{variable}))

	variables, err = cs.ah.GetVariables(ctx, types.ObjectKindProject, path.Join("org", org.Name, pg01.Name, spg01.Name, project.Name), false)
	testutil.NilError(t, err)

	assert.Assert(t, cmpDiffObject(variables, []*types.Variable{variable}))
}

func TestOrgMembers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	cs := setupConfigstore(ctx, t, log, dir)

	t.Logf("starting cs")
	go func() { _ = cs.Run(ctx) }()

	user, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
	testutil.NilError(t, err)

	org, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: "org01", Visibility: types.VisibilityPublic, CreatorUserID: user.ID})
	testutil.NilError(t, err)

	t.Run("test user org creator is org member with owner role", func(t *testing.T) {
		expectedResponse := &action.GetUserOrgsResponse{
			UserOrgs: []*action.UserOrg{
				{
					Organization: org,
					Role:         types.MemberRoleOwner,
				},
			},
		}
		res, err := cs.ah.GetUserOrgs(ctx, &action.GetUserOrgsRequest{UserRef: user.ID})
		testutil.NilError(t, err)

		assert.Assert(t, cmpDiffObject(res, expectedResponse))
	})

	orgs := []*types.Organization{}
	for i := 0; i < 10; i++ {
		org, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: fmt.Sprintf("org%d", i), Visibility: types.VisibilityPublic, CreatorUserID: user.ID})
		testutil.NilError(t, err)

		orgs = append(orgs, org)
	}

	for i := 0; i < 5; i++ {
		err := cs.ah.DeleteOrg(ctx, fmt.Sprintf("org%d", i))
		testutil.NilError(t, err)
	}

	// delete some org and check that if also orgmembers aren't yet cleaned only the existing orgs are reported
	t.Run("test only existing orgs are reported", func(t *testing.T) {
		expectedResponse := &action.GetUserOrgsResponse{
			UserOrgs: []*action.UserOrg{
				{
					Organization: org,
					Role:         types.MemberRoleOwner,
				},
			},
		}
		for i := 5; i < 10; i++ {
			expectedResponse.UserOrgs = append(expectedResponse.UserOrgs, &action.UserOrg{
				Organization: orgs[i],
				Role:         types.MemberRoleOwner,
			})
		}
		res, err := cs.ah.GetUserOrgs(ctx, &action.GetUserOrgsRequest{UserRef: user.ID})
		testutil.NilError(t, err)

		assert.Assert(t, cmpDiffObject(res, expectedResponse))
	})
}

func TestGetRemoteSources(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	cs := setupConfigstore(ctx, t, log, dir)

	t.Logf("starting cs")
	go func() { _ = cs.Run(ctx) }()

	remoteSources := []*types.RemoteSource{}
	for i := 1; i < 10; i++ {
		remoteSource, err := cs.ah.CreateRemoteSource(ctx, &action.CreateUpdateRemoteSourceRequest{Name: fmt.Sprintf("rs%d", i), Type: types.RemoteSourceTypeGitea, AuthType: types.RemoteSourceAuthTypePassword, APIURL: "http://example.com"})
		testutil.NilError(t, err)

		remoteSources = append(remoteSources, remoteSource)
	}

	tests := []struct {
		name                string
		limit               int
		sortDirection       types.SortDirection
		expectedCallsNumber int
	}{
		{
			name:                "test get remote sources with limit = 0 and no sortdirection",
			expectedCallsNumber: 1,
		},
		{
			name:                "test get remote sources with limit = 0",
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get remote sources with limit less than remote sources",
			limit:               2,
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 5,
		},
		{
			name:                "test get remote sources with limit greater than remote sources",
			limit:               10,
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get remote sources with limit = 0 and sortDirection desc",
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get remote sources with limit less than remote sources and sortDirection desc",
			limit:               2,
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 5,
		},
		{
			name:                "test get remote sources with limit greater than remote sources and sortDirection desc",
			limit:               10,
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			expectedRemoteSources := append([]*types.RemoteSource{}, remoteSources...)
			// default sortdirection is asc

			// reverse if sortDirection is desc
			// TODO(sgotti) use go 1.21 generics slices.Reverse when removing support for go < 1.21
			if tt.sortDirection == types.SortDirectionDesc {
				for i, j := 0, len(expectedRemoteSources)-1; i < j; i, j = i+1, j-1 {
					expectedRemoteSources[i], expectedRemoteSources[j] = expectedRemoteSources[j], expectedRemoteSources[i]
				}
			}

			callsNumber := 0
			var respAllRemoteSources []*types.RemoteSource
			var startRemoteSourceName string

			for {
				res, err := cs.ah.GetRemoteSources(ctx, &action.GetRemoteSourcesRequest{StartRemoteSourceName: startRemoteSourceName, Limit: tt.limit, SortDirection: tt.sortDirection})
				testutil.NilError(t, err)

				callsNumber++

				respAllRemoteSources = append(respAllRemoteSources, res.RemoteSources...)

				if !res.HasMore {
					break
				}

				lastRemoteSource := res.RemoteSources[len(res.RemoteSources)-1]
				startRemoteSourceName = lastRemoteSource.Name
			}

			assert.Assert(t, cmpDiffObject(expectedRemoteSources, respAllRemoteSources))
			assert.Assert(t, cmp.Equal(callsNumber, tt.expectedCallsNumber))
		})
	}
}

func TestGetUsers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	cs := setupConfigstore(ctx, t, log, dir)

	t.Logf("starting cs")
	go func() { _ = cs.Run(ctx) }()

	users := []*types.User{}
	for i := 1; i < 10; i++ {
		user, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: fmt.Sprintf("user%d", i)})
		testutil.NilError(t, err)

		users = append(users, user)
	}

	tests := []struct {
		name                string
		limit               int
		sortDirection       types.SortDirection
		expectedCallsNumber int
	}{
		{
			name:                "test get users with limit = 0 and no sortdirection",
			expectedCallsNumber: 1,
		},
		{
			name:                "test get users with limit = 0",
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get users with limit less than users",
			limit:               2,
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 5,
		},
		{
			name:                "test get users with limit greater than users",
			limit:               10,
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get users with limit = 0 and sortDirection desc",
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get users with limit less than users and sortDirection desc",
			limit:               2,
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 5,
		},
		{
			name:                "test get users with limit greater than users and sortDirection desc",
			limit:               10,
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			expectedUsers := append([]*types.User{}, users...)
			// default sortdirection is asc

			// reverse if sortDirection is desc
			// TODO(sgotti) use go 1.21 generics slices.Reverse when removing support for go < 1.21
			if tt.sortDirection == types.SortDirectionDesc {
				for i, j := 0, len(expectedUsers)-1; i < j; i, j = i+1, j-1 {
					expectedUsers[i], expectedUsers[j] = expectedUsers[j], expectedUsers[i]
				}
			}

			callsNumber := 0
			var respAllUsers []*types.User
			var startUserName string

			for {
				res, err := cs.ah.GetUsers(ctx, &action.GetUsersRequest{StartUserName: startUserName, Limit: tt.limit, SortDirection: tt.sortDirection})
				testutil.NilError(t, err)

				callsNumber++

				respAllUsers = append(respAllUsers, res.Users...)

				if !res.HasMore {
					break
				}

				lastUser := res.Users[len(res.Users)-1]
				startUserName = lastUser.Name
			}

			assert.Assert(t, cmpDiffObject(expectedUsers, respAllUsers))
			assert.Assert(t, cmp.Equal(callsNumber, tt.expectedCallsNumber))
		})
	}
}

func TestGetOrgs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	cs := setupConfigstore(ctx, t, log, dir)

	t.Logf("starting cs")
	go func() { _ = cs.Run(ctx) }()

	allOrgs := []*types.Organization{}
	publicOrgs := []*types.Organization{}
	for i := 1; i < 19; i++ {
		// mix public with private visiblity
		visibility := types.VisibilityPublic
		if i%2 == 0 {
			visibility = types.VisibilityPrivate
		}
		org, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: fmt.Sprintf("org%02d", i), Visibility: visibility})
		testutil.NilError(t, err)

		allOrgs = append(allOrgs, org)
		if visibility == types.VisibilityPublic {
			publicOrgs = append(publicOrgs, org)
		}
	}

	tests := []struct {
		name                string
		getPublicOrgsOnly   bool
		limit               int
		sortDirection       types.SortDirection
		expectedCallsNumber int
	}{
		{
			name:                "test get public orgs with limit = 0 and no sortdirection",
			getPublicOrgsOnly:   true,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get public orgs with limit = 0",
			getPublicOrgsOnly:   true,
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get public/private orgs with limit = 0",
			getPublicOrgsOnly:   false,
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get public orgs with limit less than orgs",
			getPublicOrgsOnly:   true,
			limit:               2,
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 5,
		},
		{
			name:                "test get public orgs with limit greater than orgs",
			getPublicOrgsOnly:   true,
			limit:               10,
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get public/private orgs with limit less than orgs",
			getPublicOrgsOnly:   false,
			limit:               3,
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 6,
		},
		{
			name:                "test get public/private orgs with limit greater than orgs",
			getPublicOrgsOnly:   false,
			limit:               20,
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get public orgs with limit = 0 and sortDirection desc",
			getPublicOrgsOnly:   true,
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get public/private orgs with limit = 0 and sortDirection desc",
			getPublicOrgsOnly:   false,
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get public orgs with limit less than orgs and sortDirection desc",
			getPublicOrgsOnly:   true,
			limit:               2,
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 5,
		},
		{
			name:                "test get public orgs with limit greater than orgs and sortDirection desc",
			getPublicOrgsOnly:   true,
			limit:               10,
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get public orgs with limit less than orgs and sortDirection desc",
			getPublicOrgsOnly:   true,
			limit:               3,
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 3,
		},
		{
			name:                "test get public/private orgs with limit less than orgs and sortDirection desc",
			getPublicOrgsOnly:   false,
			limit:               3,
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 6,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			visibilities := []types.Visibility{types.VisibilityPublic}
			// populate the expected orgs and client
			expectedOrgs := []*types.Organization{}
			if tt.getPublicOrgsOnly {
				expectedOrgs = append(expectedOrgs, publicOrgs...)
			} else {
				expectedOrgs = append(expectedOrgs, allOrgs...)
				visibilities = append(visibilities, types.VisibilityPrivate)
			}
			// default sortdirection is asc

			// reverse if sortDirection is desc
			// TODO(sgotti) use go 1.21 generics slices.Reverse when removing support for go < 1.21
			if tt.sortDirection == types.SortDirectionDesc {
				for i, j := 0, len(expectedOrgs)-1; i < j; i, j = i+1, j-1 {
					expectedOrgs[i], expectedOrgs[j] = expectedOrgs[j], expectedOrgs[i]
				}
			}

			callsNumber := 0
			var startOrgName string
			var respAllOrgs []*types.Organization

			for {
				res, err := cs.ah.GetOrgs(ctx, &action.GetOrgsRequest{StartOrgName: startOrgName, Visibilities: visibilities, Limit: tt.limit, SortDirection: tt.sortDirection})
				testutil.NilError(t, err)

				callsNumber++

				respAllOrgs = append(respAllOrgs, res.Orgs...)

				if !res.HasMore {
					break
				}

				lastOrg := res.Orgs[len(res.Orgs)-1]
				startOrgName = lastOrg.Name
			}

			assert.Assert(t, cmpDiffObject(expectedOrgs, respAllOrgs))
			assert.Assert(t, cmp.Equal(callsNumber, tt.expectedCallsNumber))
		})
	}
}

func TestGetOrgMembers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	cs := setupConfigstore(ctx, t, log, dir)

	t.Logf("starting cs")
	go func() { _ = cs.Run(ctx) }()

	users := []*types.User{}
	for i := 1; i < 10; i++ {
		user, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: fmt.Sprintf("user%d", i)})
		testutil.NilError(t, err)

		users = append(users, user)
	}

	org, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: "org01", Visibility: types.VisibilityPublic, CreatorUserID: users[0].ID})
	testutil.NilError(t, err)

	for _, user := range users {
		_, err := cs.ah.AddOrgMember(ctx, org.ID, user.ID, types.MemberRoleMember)
		testutil.NilError(t, err)
	}

	tests := []struct {
		name                string
		limit               int
		sortDirection       types.SortDirection
		expectedCallsNumber int
	}{
		{
			name:                "test get org members with limit = 0 and no sortdirection",
			expectedCallsNumber: 1,
		},
		{
			name:                "test get org members with limit = 0",
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get org members with limit less than org members",
			limit:               2,
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 5,
		},
		{
			name:                "test get org members with limit greater than org members",
			limit:               10,
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get org members with limit = 0 and sortDirection desc",
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get org members with limit less than org members and sortDirection desc",
			limit:               2,
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 5,
		},
		{
			name:                "test get org members with limit greater than org members and sortDirection desc",
			limit:               10,
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			expectedUsers := append([]*types.User{}, users...)
			// default sortdirection is asc

			// reverse if sortDirection is desc
			// TODO(sgotti) use go 1.21 generics slices.Reverse when removing support for go < 1.21
			if tt.sortDirection == types.SortDirectionDesc {
				for i, j := 0, len(expectedUsers)-1; i < j; i, j = i+1, j-1 {
					expectedUsers[i], expectedUsers[j] = expectedUsers[j], expectedUsers[i]
				}
			}

			callsNumber := 0
			var startUserName string
			var respAllOrgMembers []*action.OrgMember

			for {
				res, err := cs.ah.GetOrgMembers(ctx, &action.GetOrgMembersRequest{OrgRef: org.ID, StartUserName: startUserName, Limit: tt.limit, SortDirection: tt.sortDirection})
				testutil.NilError(t, err)

				callsNumber++

				respAllOrgMembers = append(respAllOrgMembers, res.OrgMembers...)

				if !res.HasMore {
					break
				}

				lastOrgMember := res.OrgMembers[len(res.OrgMembers)-1]
				startUserName = lastOrgMember.User.Name
			}

			orgMemberUsers := []*types.User{}
			for _, orgMember := range respAllOrgMembers {
				orgMemberUsers = append(orgMemberUsers, orgMember.User)
			}

			assert.Assert(t, cmpDiffObject(expectedUsers, orgMemberUsers))
			assert.Assert(t, cmp.Equal(callsNumber, tt.expectedCallsNumber))
		})
	}
}

func TestGetUserOrgs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	cs := setupConfigstore(ctx, t, log, dir)

	t.Logf("starting cs")
	go func() { _ = cs.Run(ctx) }()

	user, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "orguser01"})
	testutil.NilError(t, err)

	orgs := []*types.Organization{}
	for i := 1; i < 10; i++ {
		org, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: fmt.Sprintf("org%d", i), Visibility: types.VisibilityPublic})
		testutil.NilError(t, err)

		orgs = append(orgs, org)
	}

	for _, org := range orgs {
		_, err := cs.ah.AddOrgMember(ctx, org.ID, user.ID, types.MemberRoleMember)
		testutil.NilError(t, err)
	}

	tests := []struct {
		name                string
		limit               int
		sortDirection       types.SortDirection
		expectedCallsNumber int
	}{
		{
			name:                "test get user orgs with limit = 0 and no sortdirection",
			expectedCallsNumber: 1,
		},
		{
			name:                "test get user orgs with limit = 0",
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get user orgs with limit less than user orgs",
			limit:               2,
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 5,
		},
		{
			name:                "test get user orgs with limit greater than user orgs",
			limit:               10,
			sortDirection:       types.SortDirectionAsc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get user orgs with limit = 0 and sortDirection desc",
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
		{
			name:                "test get user orgs with limit less than user orgs and sortDirection desc",
			limit:               2,
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 5,
		},
		{
			name:                "test get user orgs with limit greater than user orgs and sortDirection desc",
			limit:               10,
			sortDirection:       types.SortDirectionDesc,
			expectedCallsNumber: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			expectedOrgs := append([]*types.Organization{}, orgs...)
			// default sortdirection is asc

			// reverse if sortDirection is desc
			// TODO(sgotti) use go 1.21 generics slices.Reverse when removing support for go < 1.21
			if tt.sortDirection == types.SortDirectionDesc {
				for i, j := 0, len(expectedOrgs)-1; i < j; i, j = i+1, j-1 {
					expectedOrgs[i], expectedOrgs[j] = expectedOrgs[j], expectedOrgs[i]
				}
			}

			callsNumber := 0
			var startOrgName string
			var respAllUserOrgs []*action.UserOrg

			for {
				res, err := cs.ah.GetUserOrgs(ctx, &action.GetUserOrgsRequest{UserRef: user.ID, StartOrgName: startOrgName, Limit: tt.limit, SortDirection: tt.sortDirection})
				testutil.NilError(t, err)

				callsNumber++

				respAllUserOrgs = append(respAllUserOrgs, res.UserOrgs...)

				if !res.HasMore {
					break
				}

				lastUserOrg := res.UserOrgs[len(res.UserOrgs)-1]
				startOrgName = lastUserOrg.Organization.Name
			}

			userOrgOrganizations := []*types.Organization{}
			for _, userOrg := range respAllUserOrgs {
				userOrgOrganizations = append(userOrgOrganizations, userOrg.Organization)
			}

			assert.Assert(t, cmpDiffObject(expectedOrgs, userOrgOrganizations))
			assert.Assert(t, cmp.Equal(callsNumber, tt.expectedCallsNumber))
		})
	}
}

func TestRemoteSource(t *testing.T) {
	t.Parallel()

	log := testutil.NewLogger(t)

	tests := []struct {
		name string
		f    func(ctx context.Context, t *testing.T, cs *Configstore)
	}{
		{
			name: "test create remote source",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				rsreq := &action.CreateUpdateRemoteSourceRequest{
					Name:               "rs01",
					APIURL:             "https://api.example.com",
					Type:               types.RemoteSourceTypeGitea,
					AuthType:           types.RemoteSourceAuthTypeOauth2,
					Oauth2ClientID:     "clientid",
					Oauth2ClientSecret: "clientsecret",
				}
				_, err := cs.ah.CreateRemoteSource(ctx, rsreq)
				testutil.NilError(t, err)
			},
		},
		{
			name: "test create duplicate remote source",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				rsreq := &action.CreateUpdateRemoteSourceRequest{
					Name:               "rs01",
					APIURL:             "https://api.example.com",
					Type:               types.RemoteSourceTypeGitea,
					AuthType:           types.RemoteSourceAuthTypeOauth2,
					Oauth2ClientID:     "clientid",
					Oauth2ClientSecret: "clientsecret",
				}
				_, err := cs.ah.CreateRemoteSource(ctx, rsreq)
				testutil.NilError(t, err)

				expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf(`remotesource "rs01" already exists`))
				_, err = cs.ah.CreateRemoteSource(ctx, rsreq)
				assert.Error(t, err, expectedErr.Error())
			},
		},
		{
			name: "test rename remote source",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				rsreq := &action.CreateUpdateRemoteSourceRequest{
					Name:               "rs01",
					APIURL:             "https://api.example.com",
					Type:               types.RemoteSourceTypeGitea,
					AuthType:           types.RemoteSourceAuthTypeOauth2,
					Oauth2ClientID:     "clientid",
					Oauth2ClientSecret: "clientsecret",
				}
				_, err := cs.ah.CreateRemoteSource(ctx, rsreq)
				testutil.NilError(t, err)

				rsreq.Name = "rs02"
				_, err = cs.ah.UpdateRemoteSource(ctx, "rs01", rsreq)
				testutil.NilError(t, err)
			},
		},
		{
			name: "test update remote source keeping same name",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				rsreq := &action.CreateUpdateRemoteSourceRequest{
					Name:               "rs01",
					APIURL:             "https://api.example.com",
					Type:               types.RemoteSourceTypeGitea,
					AuthType:           types.RemoteSourceAuthTypeOauth2,
					Oauth2ClientID:     "clientid",
					Oauth2ClientSecret: "clientsecret",
				}
				_, err := cs.ah.CreateRemoteSource(ctx, rsreq)
				testutil.NilError(t, err)

				rsreq.APIURL = "https://api01.example.com"
				_, err = cs.ah.UpdateRemoteSource(ctx, "rs01", rsreq)
				testutil.NilError(t, err)
			},
		},
		{
			name: "test rename remote source to an already existing name",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				rs01req := &action.CreateUpdateRemoteSourceRequest{
					Name:               "rs01",
					APIURL:             "https://api.example.com",
					Type:               types.RemoteSourceTypeGitea,
					AuthType:           types.RemoteSourceAuthTypeOauth2,
					Oauth2ClientID:     "clientid",
					Oauth2ClientSecret: "clientsecret",
				}
				_, err := cs.ah.CreateRemoteSource(ctx, rs01req)
				testutil.NilError(t, err)

				rs02req := &action.CreateUpdateRemoteSourceRequest{
					Name:               "rs02",
					APIURL:             "https://api.example.com",
					Type:               types.RemoteSourceTypeGitea,
					AuthType:           types.RemoteSourceAuthTypeOauth2,
					Oauth2ClientID:     "clientid",
					Oauth2ClientSecret: "clientsecret",
				}
				_, err = cs.ah.CreateRemoteSource(ctx, rs02req)
				testutil.NilError(t, err)

				expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf(`remotesource "rs02" already exists`))
				rs01req.Name = "rs02"
				_, err = cs.ah.UpdateRemoteSource(ctx, "rs01", rs01req)
				assert.Error(t, err, expectedErr.Error())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			ctx := context.Background()

			cs := setupConfigstore(ctx, t, log, dir)

			t.Logf("starting cs")
			go func() { _ = cs.Run(ctx) }()

			tt.f(ctx, t, cs)
		})
	}
}

func TestDeleteUser(t *testing.T) {
	t.Parallel()

	log := testutil.NewLogger(t)

	tests := []struct {
		name string
		f    func(ctx context.Context, t *testing.T, cs *Configstore)
	}{
		{
			name: "test delete user by id",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				users, err := getUsers(ctx, cs)
				testutil.NilError(t, err)

				err = cs.ah.DeleteUser(ctx, users[0].ID)
				testutil.NilError(t, err)
			},
		},
		{
			name: "test delete user by name",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				users, err := getUsers(ctx, cs)
				testutil.NilError(t, err)

				err = cs.ah.DeleteUser(ctx, users[0].Name)
				testutil.NilError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			ctx := context.Background()

			cs := setupConfigstore(ctx, t, log, dir)

			t.Logf("starting cs")

			_, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
			testutil.NilError(t, err)

			// create related entries
			// add new entries related to user when needed to properly test
			// that all will be removed alongside the user
			_, err = cs.ah.CreateRemoteSource(ctx, &action.CreateUpdateRemoteSourceRequest{Name: "rs01", Type: types.RemoteSourceTypeGitea, AuthType: types.RemoteSourceAuthTypePassword, APIURL: "http://example.com"})
			testutil.NilError(t, err)

			_, err = cs.ah.CreateUserLA(ctx, &action.CreateUserLARequest{UserRef: "user01", RemoteSourceName: "rs01"})
			testutil.NilError(t, err)

			_, err = cs.ah.CreateUserToken(ctx, "user01", "token01")
			testutil.NilError(t, err)

			_, err = cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: "org01", Visibility: types.VisibilityPublic})
			testutil.NilError(t, err)

			_, err = cs.ah.AddOrgMember(ctx, "org01", "user01", types.MemberRoleMember)
			testutil.NilError(t, err)

			_, err = cs.ah.CreateOrgInvitation(ctx, &action.CreateOrgInvitationRequest{OrganizationRef: "org01", UserRef: "user01", Role: types.MemberRoleMember})
			testutil.NilError(t, err)

			go func() { _ = cs.Run(ctx) }()

			tt.f(ctx, t, cs)

			users, err := getUsers(ctx, cs)
			testutil.NilError(t, err)

			assert.Assert(t, cmp.Len(users, 0))
		})
	}
}

func TestDeleteOrg(t *testing.T) {
	t.Parallel()

	log := testutil.NewLogger(t)

	tests := []struct {
		name string
		f    func(ctx context.Context, t *testing.T, cs *Configstore)
	}{
		{
			name: "test delete org by id",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				orgs, err := getOrgs(ctx, cs)
				testutil.NilError(t, err)

				err = cs.ah.DeleteOrg(ctx, orgs[0].ID)
				testutil.NilError(t, err)
			},
		},
		{
			name: "test delete org by name",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				orgs, err := getOrgs(ctx, cs)
				testutil.NilError(t, err)

				err = cs.ah.DeleteOrg(ctx, orgs[0].Name)
				testutil.NilError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			ctx := context.Background()

			cs := setupConfigstore(ctx, t, log, dir)

			t.Logf("starting cs")

			_, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: "org01", Visibility: types.VisibilityPublic})
			testutil.NilError(t, err)

			// create related entries
			// add new entries related to org when needed to properly test
			// that all will be removed alongside the org
			_, err = cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
			testutil.NilError(t, err)

			_, err = cs.ah.AddOrgMember(ctx, "org01", "user01", types.MemberRoleMember)
			testutil.NilError(t, err)

			_, err = cs.ah.CreateOrgInvitation(ctx, &action.CreateOrgInvitationRequest{OrganizationRef: "org01", UserRef: "user01", Role: types.MemberRoleMember})
			testutil.NilError(t, err)

			go func() { _ = cs.Run(ctx) }()

			tt.f(ctx, t, cs)

			orgs, err := getOrgs(ctx, cs)
			testutil.NilError(t, err)

			assert.Assert(t, cmp.Len(orgs, 0))
		})
	}
}

func TestOrgInvitation(t *testing.T) {
	t.Parallel()

	log := testutil.NewLogger(t)

	setupUsers := func(t *testing.T, ctx context.Context, cs *Configstore) {
		for i := 1; i < 5; i++ {
			_, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: fmt.Sprintf("user%d", i)})
			testutil.NilError(t, err)
		}
	}

	setupOrgs := func(t *testing.T, ctx context.Context, cs *Configstore, creatorUserID string) {
		for i := 1; i < 5; i++ {
			_, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: fmt.Sprintf("org%d", i), Visibility: "public", CreatorUserID: creatorUserID})
			testutil.NilError(t, err)
		}
	}

	tests := []struct {
		name string
		f    func(ctx context.Context, t *testing.T, cs *Configstore)
	}{
		{
			name: "test create org invitation",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				setupUsers(t, ctx, cs)
				users, err := getUsers(ctx, cs)
				testutil.NilError(t, err)

				userOwner := users[0]
				userInvitation := users[1]

				setupOrgs(t, ctx, cs, userOwner.ID)
				orgs, err := getOrgs(ctx, cs)
				testutil.NilError(t, err)

				org := orgs[0]

				rs := &action.CreateOrgInvitationRequest{
					UserRef:         userInvitation.ID,
					OrganizationRef: org.ID,
					Role:            types.MemberRoleMember,
				}
				_, err = cs.ah.CreateOrgInvitation(ctx, rs)
				testutil.NilError(t, err)

				fmt.Println("err:", err)
			},
		},
		{
			name: "test user org invitation creation with already existing invitation",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				setupUsers(t, ctx, cs)
				users, err := getUsers(ctx, cs)
				testutil.NilError(t, err)

				userOwner := users[0]
				userInvitation := users[1]

				setupOrgs(t, ctx, cs, userOwner.ID)
				orgs, err := getOrgs(ctx, cs)
				testutil.NilError(t, err)

				org := orgs[0]

				rs := &action.CreateOrgInvitationRequest{
					UserRef:         userInvitation.ID,
					OrganizationRef: org.ID,
					Role:            types.MemberRoleMember,
				}
				_, err = cs.ah.CreateOrgInvitation(ctx, rs)
				testutil.NilError(t, err)

				expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("invitation already exists"))
				_, err = cs.ah.CreateOrgInvitation(ctx, rs)
				assert.Error(t, err, expectedErr.Error())
			},
		},
		{
			name: "test org deletion with existing org invitations",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				setupUsers(t, ctx, cs)
				users, err := getUsers(ctx, cs)
				testutil.NilError(t, err)

				userOwner := users[0]
				userInvitation := users[1]

				setupOrgs(t, ctx, cs, userOwner.ID)
				orgs, err := getOrgs(ctx, cs)
				testutil.NilError(t, err)

				org := orgs[0]

				rs := &action.CreateOrgInvitationRequest{
					UserRef:         userInvitation.ID,
					OrganizationRef: org.ID,
					Role:            types.MemberRoleMember,
				}
				_, err = cs.ah.CreateOrgInvitation(ctx, rs)
				testutil.NilError(t, err)

				err = cs.ah.DeleteOrg(ctx, org.ID)
				testutil.NilError(t, err)

				orgInvitations, err := cs.ah.GetUserOrgInvitations(ctx, userInvitation.ID)
				testutil.NilError(t, err)

				assert.Assert(t, cmp.Len(orgInvitations, 0))
			},
		},
		{
			name: "test user deletion with existing org invitations",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				setupUsers(t, ctx, cs)
				users, err := getUsers(ctx, cs)
				testutil.NilError(t, err)

				userOwner := users[0]
				userInvitation := users[1]

				setupOrgs(t, ctx, cs, userOwner.ID)
				orgs, err := getOrgs(ctx, cs)
				testutil.NilError(t, err)

				org := orgs[0]

				rs := &action.CreateOrgInvitationRequest{
					UserRef:         userInvitation.ID,
					OrganizationRef: org.ID,
					Role:            types.MemberRoleMember,
				}
				_, err = cs.ah.CreateOrgInvitation(ctx, rs)
				testutil.NilError(t, err)

				err = cs.ah.DeleteUser(ctx, userInvitation.ID)
				testutil.NilError(t, err)

				orgInvitations, err := cs.ah.GetOrgInvitations(ctx, org.ID)
				testutil.NilError(t, err)

				assert.Assert(t, cmp.Len(orgInvitations, 0))
			},
		},
		{
			name: "test add org member with an existing org invitation",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				setupUsers(t, ctx, cs)
				users, err := getUsers(ctx, cs)
				testutil.NilError(t, err)

				userOwner := users[0]
				userInvitation := users[1]

				setupOrgs(t, ctx, cs, userOwner.ID)

				orgs, err := getOrgs(ctx, cs)
				testutil.NilError(t, err)

				org := orgs[0]

				rs := &action.CreateOrgInvitationRequest{
					UserRef:         userInvitation.ID,
					OrganizationRef: org.ID,
					Role:            types.MemberRoleMember,
				}
				_, err = cs.ah.CreateOrgInvitation(ctx, rs)
				testutil.NilError(t, err)

				_, err = cs.ah.AddOrgMember(ctx, org.ID, userInvitation.ID, types.MemberRoleMember)
				testutil.NilError(t, err)

				orgInvitations, err := cs.ah.GetOrgInvitations(ctx, org.ID)
				testutil.NilError(t, err)

				assert.Assert(t, cmp.Len(orgInvitations, 0))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			ctx := context.Background()

			cs := setupConfigstore(ctx, t, log, dir)

			t.Logf("starting cs")
			go func() { _ = cs.Run(ctx) }()

			tt.f(ctx, t, cs)
		})
	}
}
