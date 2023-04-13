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

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/rs/zerolog"
	"github.com/sorintlab/errors"

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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	ostDir, err := os.MkdirTemp(dir, "ost")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	csDir, err := os.MkdirTemp(dir, "cs")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	return cs
}

func setupUsers(t *testing.T, ctx context.Context, cs *Configstore) {
	i := 1
	for i < 5 {
		req := &action.CreateUserRequest{
			UserName: "UserTest" + fmt.Sprint(i),
		}
		_, err := cs.ah.CreateUser(ctx, req)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		i++
	}
}

func setupOrgs(t *testing.T, ctx context.Context, cs *Configstore, userMemberID string) {
	i := 1
	for i < 5 {
		req := &action.CreateOrgRequest{
			Name:       "OrgTest" + fmt.Sprint(i),
			Visibility: "public",
		}
		org, err := cs.ah.CreateOrg(ctx, req)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		_, err = cs.ah.AddOrgMember(ctx, org.ID, userMemberID, types.MemberRoleOwner)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		i++
	}
}

func getRemoteSources(ctx context.Context, cs *Configstore) ([]*types.RemoteSource, error) {
	var users []*types.RemoteSource
	err := cs.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		users, err = cs.d.GetRemoteSources(tx, "", 0, true)
		return errors.WithStack(err)
	})

	return users, errors.WithStack(err)
}
func getUsers(ctx context.Context, cs *Configstore) ([]*types.User, error) {
	var users []*types.User
	err := cs.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		users, err = cs.d.GetUsers(tx, "", 0, true)
		return errors.WithStack(err)
	})

	return users, errors.WithStack(err)
}

func getOrgs(ctx context.Context, cs *Configstore) ([]*types.Organization, error) {
	var orgs []*types.Organization
	err := cs.d.Do(ctx, func(tx *sql.Tx) error {
		var err error
		orgs, err = cs.d.GetOrgs(tx, "", 0, true)
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

func cmpDiffObject(x, y interface{}) string {
	// Since postgres has microsecond time precision while go has nanosecond time precision we should check times with a microsecond margin
	return cmp.Diff(x, y, cmpopts.IgnoreFields(sqlg.ObjectMeta{}, "TxID"), cmpopts.EquateApproxTime(1*time.Microsecond))
}

func TestExportImport(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := context.Background()
	log := testutil.NewLogger(t)

	cs := setupConfigstore(ctx, t, log, dir)

	t.Logf("starting cs")
	go func() { _ = cs.Run(ctx) }()

	time.Sleep(1 * time.Second)

	var expectedRemoteSourcesCount int
	var expectedUsersCount int
	var expectedOrgsCount int
	var expectedProjectGroupsCount int
	var expectedProjectsCount int
	var expectedSecretsCount int
	var expectedVariablesCount int

	if _, err := cs.ah.CreateRemoteSource(ctx, &action.CreateUpdateRemoteSourceRequest{Name: "rs01", Type: types.RemoteSourceTypeGitea, AuthType: types.RemoteSourceAuthTypePassword, APIURL: "http://example.com"}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	expectedRemoteSourcesCount++

	for i := 0; i < 10; i++ {
		if _, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: fmt.Sprintf("user%d", i)}); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		expectedUsersCount++
		expectedProjectGroupsCount++
	}

	time.Sleep(5 * time.Second)

	// Do some more changes
	for i := 10; i < 20; i++ {
		if _, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: fmt.Sprintf("user%d", i)}); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		expectedUsersCount++
		expectedProjectGroupsCount++
	}

	user, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	expectedUsersCount++
	expectedProjectGroupsCount++

	org, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: "org01", Visibility: types.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	expectedOrgsCount++
	expectedProjectGroupsCount++

	if _, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	expectedProjectsCount++

	if _, err := cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	expectedProjectGroupsCount++

	if _, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	expectedProjectsCount++

	if _, err := cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	expectedProjectGroupsCount++

	if _, err := cs.ah.CreateSecret(ctx, &action.CreateUpdateSecretRequest{Name: "secret01", Parent: types.Parent{Kind: types.ObjectKindProject, ID: path.Join("user", user.Name, "projectgroup01", "project01")}, Type: types.SecretTypeInternal, Data: map[string]string{"secret01": "secretvar01"}}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	expectedSecretsCount++

	if _, err := cs.ah.CreateVariable(ctx, &action.CreateUpdateVariableRequest{Name: "variable01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Values: []types.VariableValue{{SecretName: "secret01", SecretVar: "secretvar01"}}}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	expectedVariablesCount++

	remoteSources, err := getRemoteSources(ctx, cs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	users, err := getUsers(ctx, cs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	orgs, err := getOrgs(ctx, cs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	projectGroups, err := getProjectGroups(ctx, cs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	projects, err := getProjects(ctx, cs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	secrets, err := getSecrets(ctx, cs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	variables, err := getVariables(ctx, cs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if len(remoteSources) != expectedRemoteSourcesCount {
		t.Logf("remoteSources: %s", util.Dump(remoteSources))
		t.Fatalf("expected %d remoteSources, got %d remoteSources", expectedRemoteSourcesCount, len(remoteSources))
	}
	if len(users) != expectedUsersCount {
		t.Logf("users: %s", util.Dump(users))
		t.Fatalf("expected %d users, got %d users", expectedUsersCount, len(users))
	}
	if len(orgs) != expectedOrgsCount {
		t.Logf("orgs: %s", util.Dump(orgs))
		t.Fatalf("expected %d orgs, got %d orgs", expectedOrgsCount, len(orgs))
	}
	if len(projectGroups) != expectedProjectGroupsCount {
		t.Logf("projectGroups: %s", util.Dump(projectGroups))
		t.Fatalf("expected %d projectGroups, got %d projectGroups", expectedProjectGroupsCount, len(projectGroups))
	}
	if len(projects) != expectedProjectsCount {
		t.Logf("projects: %s", util.Dump(projects))
		t.Fatalf("expected %d projects, got %d projects", expectedProjectsCount, len(projects))
	}
	if len(secrets) != expectedSecretsCount {
		t.Logf("secrets: %s", util.Dump(secrets))
		t.Fatalf("expected %d secrets, got %d secrets", expectedSecretsCount, len(secrets))
	}
	if len(variables) != expectedVariablesCount {
		t.Logf("variables: %s", util.Dump(variables))
		t.Fatalf("expected %d variables, got %d variables", expectedVariablesCount, len(variables))
	}

	var export bytes.Buffer
	if err := cs.ah.Export(ctx, &export); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if err := cs.ah.MaintenanceMode(ctx, true); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	time.Sleep(5 * time.Second)

	if err := cs.ah.Import(ctx, &export); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if err := cs.ah.MaintenanceMode(ctx, false); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	time.Sleep(5 * time.Second)

	newRemoteSources, err := getRemoteSources(ctx, cs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	newUsers, err := getUsers(ctx, cs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	newOrgs, err := getOrgs(ctx, cs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	newProjectGroups, err := getProjectGroups(ctx, cs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	newProjects, err := getProjects(ctx, cs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	newSecrets, err := getSecrets(ctx, cs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	newVariables, err := getVariables(ctx, cs)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if diff := cmpDiffObject(remoteSources, newRemoteSources); diff != "" {
		t.Fatalf("remoteSources mismatch (-want +got):\n%s", diff)
	}
	if diff := cmpDiffObject(users, newUsers); diff != "" {
		t.Fatalf("users mismatch (-want +got):\n%s", diff)
	}
	if diff := cmpDiffObject(orgs, newOrgs); diff != "" {
		t.Fatalf("orgs mismatch (-want +got):\n%s", diff)
	}
	if diff := cmpDiffObject(projectGroups, newProjectGroups); diff != "" {
		t.Fatalf("projectGroups mismatch (-want +got):\n%s", diff)
	}
	if diff := cmpDiffObject(projects, newProjects); diff != "" {
		t.Fatalf("projects mismatch (-want +got):\n%s", diff)
	}
	if diff := cmpDiffObject(secrets, newSecrets); diff != "" {
		t.Fatalf("secrets mismatch (-want +got):\n%s", diff)
	}
	if diff := cmpDiffObject(variables, newVariables); diff != "" {
		t.Fatalf("variables mismatch (-want +got):\n%s", diff)
	}
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
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})

	t.Run("create duplicated user", func(t *testing.T) {
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("user with name %q already exists", "user01"))
		_, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
		if err == nil {
			t.Fatalf("expected error %v, got nil err", expectedErr)
		}
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("concurrent user with same name creation", func(t *testing.T) {
		prevUsers, err := getUsers(ctx, cs)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

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
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		if len(users) != len(prevUsers)+1 {
			t.Fatalf("expected %d users, got %d", len(prevUsers)+1, len(users))
		}
	})

	t.Run("delete user", func(t *testing.T) {
		_, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user03"})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		err = cs.ah.DeleteUser(ctx, "user03")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		var user *types.User
		err = cs.d.Do(ctx, func(tx *sql.Tx) error {
			var err error
			user, err = cs.d.GetUser(tx, "user03")
			return errors.WithStack(err)
		})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if user != nil {
			t.Fatalf("expected user nil, got: %v", user)
		}
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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	org, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: "org01", Visibility: types.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	t.Run("create a project in user root project group", func(t *testing.T) {
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("create a project in org root project group", func(t *testing.T) {
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("create a projectgroup in user root project group", func(t *testing.T) {
		_, err := cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("create a projectgroup in org root project group", func(t *testing.T) {
		_, err := cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("create a project in user non root project group with same name as a root project", func(t *testing.T) {
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("create a project in org non root project group with same name as a root project", func(t *testing.T) {
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})

	t.Run("create duplicated project in user root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with name %q, path %q already exists", projectName, path.Join("user", user.Name, projectName)))
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: projectName, Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("create duplicated project in org root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with name %q, path %q already exists", projectName, path.Join("org", org.Name, projectName)))
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: projectName, Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})

	t.Run("create duplicated project in user non root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with name %q, path %q already exists", projectName, path.Join("user", user.Name, "projectgroup01", projectName)))
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: projectName, Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("create duplicated project in org non root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with name %q, path %q already exists", projectName, path.Join("org", org.Name, "projectgroup01", projectName)))
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: projectName, Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})

	t.Run("create project in unexistent project group", func(t *testing.T) {
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf(`project group with id "unexistentid" doesn't exist`))
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: "unexistentid"}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("create project without parent id specified", func(t *testing.T) {
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project parent id required"))
		_, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})

	t.Run("concurrent project with same name creation", func(t *testing.T) {
		prevProjects, err := getProjects(ctx, cs)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

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
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		if len(projects) != len(prevProjects)+1 {
			t.Fatalf("expected %d projects, got %d", len(prevProjects)+1, len(projects))
		}
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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if _, err := cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	p01 := &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual}
	if _, err := cs.ah.CreateProject(ctx, p01); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	p02 := &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual}
	if _, err := cs.ah.CreateProject(ctx, p02); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	p03 := &action.CreateUpdateProjectRequest{Name: "project02", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual}
	if _, err := cs.ah.CreateProject(ctx, p03); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	t.Run("rename project keeping same parent", func(t *testing.T) {
		projectName := "project02"
		p03.Name = "newproject02"
		_, err := cs.ah.UpdateProject(ctx, path.Join("user", user.Name, "projectgroup01", projectName), p03)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("move project to project group having project with same name", func(t *testing.T) {
		projectName := "project01"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project with name %q, path %q already exists", projectName, path.Join("user", user.Name, projectName)))
		p02.Parent.ID = path.Join("user", user.Name)
		_, err := cs.ah.UpdateProject(ctx, path.Join("user", user.Name, "projectgroup01", projectName), p02)
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("move project to project group changing name", func(t *testing.T) {
		projectName := "project01"
		p02.Name = "newproject01"
		p02.Parent.ID = path.Join("user", user.Name)
		_, err := cs.ah.UpdateProject(ctx, path.Join("user", user.Name, "projectgroup01", projectName), p02)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	rootPG, err := cs.ah.GetProjectGroup(ctx, path.Join("user", user.Name))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	pg01req := &action.CreateUpdateProjectGroupRequest{Name: "pg01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic}
	if _, err := cs.ah.CreateProjectGroup(ctx, pg01req); err != nil {
		log.Err(err).Send()
		t.Fatalf("unexpected err: %v", err)
	}
	pg02req := &action.CreateUpdateProjectGroupRequest{Name: "pg02", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic}
	if _, err := cs.ah.CreateProjectGroup(ctx, pg02req); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	pg03req := &action.CreateUpdateProjectGroupRequest{Name: "pg03", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic}
	if _, err := cs.ah.CreateProjectGroup(ctx, pg03req); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	pg04req := &action.CreateUpdateProjectGroupRequest{Name: "pg01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "pg01")}, Visibility: types.VisibilityPublic}
	if _, err := cs.ah.CreateProjectGroup(ctx, pg04req); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	pg05req := &action.CreateUpdateProjectGroupRequest{Name: "pg01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("user", user.Name, "pg02")}, Visibility: types.VisibilityPublic}
	if _, err := cs.ah.CreateProjectGroup(ctx, pg05req); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	t.Run("rename project group keeping same parent", func(t *testing.T) {
		projectGroupName := "pg03"
		pg03req.Name = "newpg03"
		if _, err := cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name, projectGroupName), pg03req); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("move project to project group having project with same name", func(t *testing.T) {
		projectGroupName := "pg01"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group with name %q, path %q already exists", projectGroupName, path.Join("user", user.Name, projectGroupName)))
		pg05req.Parent.ID = path.Join("user", user.Name)
		_, err := cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name, "pg02", projectGroupName), pg05req)
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("move project group to root project group changing name", func(t *testing.T) {
		projectGroupName := "pg01"
		pg05req.Name = "newpg01"
		pg05req.Parent.ID = path.Join("user", user.Name)
		pg05, err := cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name, "pg02", projectGroupName), pg05req)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if pg05.Parent.ID != rootPG.ID {
			t.Fatalf("expected project group parent id as root project group id")
		}
	})
	t.Run("move project group inside itself", func(t *testing.T) {
		projectGroupName := "pg02"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot move project group inside itself or child project group"))
		pg02req.Parent.ID = path.Join("user", user.Name, "pg02")
		_, err := cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name, projectGroupName), pg02req)
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("move project group to child project group", func(t *testing.T) {
		projectGroupName := "pg01"
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot move project group inside itself or child project group"))
		pg01req.Parent.ID = path.Join("user", user.Name, "pg01", "pg01")
		_, err := cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name, projectGroupName), pg01req)
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("change root project group parent kind", func(t *testing.T) {
		var rootPG *types.ProjectGroup
		rootPG, err := cs.ah.GetProjectGroup(ctx, path.Join("user", user.Name))
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		rootPG.Parent.Kind = types.ObjectKindProjectGroup
		rootPG.Name = "rootpg"

		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("changing project group parent kind isn't supported"))
		_, err = cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name), &action.CreateUpdateProjectGroupRequest{Name: rootPG.Name, Parent: rootPG.Parent, Visibility: rootPG.Visibility})
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("change root project group parent id", func(t *testing.T) {
		var rootPG *types.ProjectGroup
		rootPG, err := cs.ah.GetProjectGroup(ctx, path.Join("user", user.Name))
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		rootPG.Parent.ID = path.Join("user", user.Name, "pg01")

		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot change root project group parent kind or id"))
		_, err = cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name), &action.CreateUpdateProjectGroupRequest{Name: rootPG.Name, Parent: rootPG.Parent, Visibility: rootPG.Visibility})
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("change root project group name", func(t *testing.T) {
		var rootPG *types.ProjectGroup
		rootPG, err := cs.ah.GetProjectGroup(ctx, path.Join("user", user.Name))
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		rootPG.Name = "rootpgnewname"

		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("project group name for root project group must be empty"))
		_, err = cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name), &action.CreateUpdateProjectGroupRequest{Name: rootPG.Name, Parent: rootPG.Parent, Visibility: rootPG.Visibility})
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("change root project group visibility", func(t *testing.T) {
		var rootPG *types.ProjectGroup
		rootPG, err := cs.ah.GetProjectGroup(ctx, path.Join("user", user.Name))
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		rootPG.Visibility = types.VisibilityPrivate

		if _, err := cs.ah.UpdateProjectGroup(ctx, path.Join("user", user.Name), &action.CreateUpdateProjectGroupRequest{Name: rootPG.Name, Parent: rootPG.Parent, Visibility: rootPG.Visibility}); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		rootPG, err = cs.ah.GetProjectGroup(ctx, path.Join("user", user.Name))
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if rootPG.Visibility != types.VisibilityPrivate {
			t.Fatalf("expected visiblity %q, got visibility: %q", types.VisibilityPublic, rootPG.Visibility)
		}
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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// create a projectgroup in org root project group
	pg01, err := cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// create a child projectgroup in org root project group
	if _, err := cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "subprojectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: pg01.ID}, Visibility: types.VisibilityPublic}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	t.Run("delete root project group", func(t *testing.T) {
		expectedErr := util.NewAPIError(util.ErrBadRequest, errors.Errorf("cannot delete root project group"))
		err := cs.ah.DeleteProjectGroup(ctx, path.Join("org", org.Name))
		if err.Error() != expectedErr.Error() {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})

	t.Run("delete project group", func(t *testing.T) {
		err := cs.ah.DeleteProjectGroup(ctx, pg01.ID)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// create a projectgroup in org root project group
	pg01, err := cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// create a child projectgroup in org root project group
	spg01, err := cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "subprojectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: pg01.ID}, Visibility: types.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// create a project inside child projectgroup
	project, err := cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: spg01.ID}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// create project secret
	if _, err := cs.ah.CreateSecret(ctx, &action.CreateUpdateSecretRequest{Name: "secret01", Parent: types.Parent{Kind: types.ObjectKindProject, ID: project.ID}, Type: types.SecretTypeInternal, Data: map[string]string{"secret01": "secretvar01"}}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	// create project variable
	if _, err = cs.ah.CreateVariable(ctx, &action.CreateUpdateVariableRequest{Name: "variable01", Parent: types.Parent{Kind: types.ObjectKindProject, ID: project.ID}, Values: []types.VariableValue{{SecretName: "secret01", SecretVar: "secretvar01"}}}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// delete projectgroup
	if err := cs.ah.DeleteProjectGroup(ctx, pg01.ID); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// recreate the same hierarchj using the paths
	pg01, err = cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "projectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	spg01, err = cs.ah.CreateProjectGroup(ctx, &action.CreateUpdateProjectGroupRequest{Name: "subprojectgroup01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name, pg01.Name)}, Visibility: types.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	project, err = cs.ah.CreateProject(ctx, &action.CreateUpdateProjectRequest{Name: "project01", Parent: types.Parent{Kind: types.ObjectKindProjectGroup, ID: path.Join("org", org.Name, pg01.Name, spg01.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	secret, err := cs.ah.CreateSecret(ctx, &action.CreateUpdateSecretRequest{Name: "secret01", Parent: types.Parent{Kind: types.ObjectKindProject, ID: path.Join("org", org.Name, pg01.Name, spg01.Name, project.Name)}, Type: types.SecretTypeInternal, Data: map[string]string{"secret01": "secretvar01"}})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	variable, err := cs.ah.CreateVariable(ctx, &action.CreateUpdateVariableRequest{Name: "variable01", Parent: types.Parent{Kind: types.ObjectKindProject, ID: path.Join("org", org.Name, pg01.Name, spg01.Name, project.Name)}, Values: []types.VariableValue{{SecretName: "secret01", SecretVar: "secretvar01"}}})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// Get by projectgroup id
	projects, err := cs.ah.GetProjectGroupProjects(ctx, spg01.ID)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmpDiffObject(projects, []*types.Project{project}); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}

	// Get by projectgroup path
	projects, err = cs.ah.GetProjectGroupProjects(ctx, path.Join("org", org.Name, pg01.Name, spg01.Name))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmpDiffObject(projects, []*types.Project{project}); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}

	secrets, err := cs.ah.GetSecrets(ctx, types.ObjectKindProject, project.ID, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmpDiffObject(secrets, []*types.Secret{secret}); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}

	secrets, err = cs.ah.GetSecrets(ctx, types.ObjectKindProject, path.Join("org", org.Name, pg01.Name, spg01.Name, project.Name), false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmpDiffObject(secrets, []*types.Secret{secret}); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}

	variables, err := cs.ah.GetVariables(ctx, types.ObjectKindProject, project.ID, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmpDiffObject(variables, []*types.Variable{variable}); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}

	variables, err = cs.ah.GetVariables(ctx, types.ObjectKindProject, path.Join("org", org.Name, pg01.Name, spg01.Name, project.Name), false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmpDiffObject(variables, []*types.Variable{variable}); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}
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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	org, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: "org01", Visibility: types.VisibilityPublic, CreatorUserID: user.ID})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	t.Run("test user org creator is org member with owner role", func(t *testing.T) {
		expectedResponse := []*action.UserOrgsResponse{
			{
				Organization: org,
				Role:         types.MemberRoleOwner,
			},
		}
		res, err := cs.ah.GetUserOrgs(ctx, user.ID)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if diff := cmpDiffObject(res, expectedResponse); diff != "" {
			t.Fatalf("mismatch (-want +got):\n%s", diff)
		}
	})

	orgs := []*types.Organization{}
	for i := 0; i < 10; i++ {
		org, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: fmt.Sprintf("org%d", i), Visibility: types.VisibilityPublic, CreatorUserID: user.ID})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		orgs = append(orgs, org)
	}

	for i := 0; i < 5; i++ {
		if err := cs.ah.DeleteOrg(ctx, fmt.Sprintf("org%d", i)); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}

	// delete some org and check that if also orgmembers aren't yet cleaned only the existing orgs are reported
	t.Run("test only existing orgs are reported", func(t *testing.T) {
		expectedResponse := []*action.UserOrgsResponse{
			{
				Organization: org,
				Role:         types.MemberRoleOwner,
			},
		}
		for i := 5; i < 10; i++ {
			expectedResponse = append(expectedResponse, &action.UserOrgsResponse{
				Organization: orgs[i],
				Role:         types.MemberRoleOwner,
			})
		}
		res, err := cs.ah.GetUserOrgs(ctx, user.ID)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if diff := cmpDiffObject(res, expectedResponse); diff != "" {
			t.Fatalf("mismatch (-want +got):\n%s", diff)
		}
	})
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
				if _, err := cs.ah.CreateRemoteSource(ctx, rsreq); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
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
				if _, err := cs.ah.CreateRemoteSource(ctx, rsreq); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				expectedError := util.NewAPIError(util.ErrBadRequest, errors.Errorf(`remotesource "rs01" already exists`))
				_, err := cs.ah.CreateRemoteSource(ctx, rsreq)
				if err.Error() != expectedError.Error() {
					t.Fatalf("expected err: %v, got err: %v", expectedError.Error(), err.Error())
				}
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
				if _, err := cs.ah.CreateRemoteSource(ctx, rsreq); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				rsreq.Name = "rs02"
				if _, err := cs.ah.UpdateRemoteSource(ctx, "rs01", rsreq); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
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
				if _, err := cs.ah.CreateRemoteSource(ctx, rsreq); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				rsreq.APIURL = "https://api01.example.com"
				if _, err := cs.ah.UpdateRemoteSource(ctx, "rs01", rsreq); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
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
				if _, err := cs.ah.CreateRemoteSource(ctx, rs01req); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				rs02req := &action.CreateUpdateRemoteSourceRequest{
					Name:               "rs02",
					APIURL:             "https://api.example.com",
					Type:               types.RemoteSourceTypeGitea,
					AuthType:           types.RemoteSourceAuthTypeOauth2,
					Oauth2ClientID:     "clientid",
					Oauth2ClientSecret: "clientsecret",
				}
				if _, err := cs.ah.CreateRemoteSource(ctx, rs02req); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				expectedError := util.NewAPIError(util.ErrBadRequest, errors.Errorf(`remotesource "rs02" already exists`))
				rs01req.Name = "rs02"
				_, err := cs.ah.UpdateRemoteSource(ctx, "rs01", rs01req)
				if err.Error() != expectedError.Error() {
					t.Fatalf("expected err: %v, got err: %v", expectedError.Error(), err.Error())
				}
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
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				if err := cs.ah.DeleteUser(ctx, users[0].ID); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

			},
		},
		{
			name: "test delete user by name",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				users, err := getUsers(ctx, cs)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				if err := cs.ah.DeleteUser(ctx, users[0].Name); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			ctx := context.Background()

			cs := setupConfigstore(ctx, t, log, dir)

			t.Logf("starting cs")

			if _, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"}); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			// create related entries
			// add new entries related to user when needed to properly test
			// that all will be removed alongside the user
			if _, err := cs.ah.CreateRemoteSource(ctx, &action.CreateUpdateRemoteSourceRequest{Name: "rs01", Type: types.RemoteSourceTypeGitea, AuthType: types.RemoteSourceAuthTypePassword, APIURL: "http://example.com"}); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if _, err := cs.ah.CreateUserLA(ctx, &action.CreateUserLARequest{UserRef: "user01", RemoteSourceName: "rs01"}); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if _, err := cs.ah.CreateUserToken(ctx, "user01", "token01"); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			if _, err := cs.ah.CreateOrg(ctx, &action.CreateOrgRequest{Name: "org01", Visibility: types.VisibilityPublic}); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if _, err := cs.ah.AddOrgMember(ctx, "org01", "user01", types.MemberRoleMember); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if _, err := cs.ah.CreateOrgInvitation(ctx, &action.CreateOrgInvitationRequest{OrganizationRef: "org01", UserRef: "user01", Role: types.MemberRoleMember}); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			go func() { _ = cs.Run(ctx) }()

			tt.f(ctx, t, cs)

			users, err := getUsers(ctx, cs)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if len(users) != 0 {
				t.Fatalf("expected 0 users, got %d users", len(users))
			}
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
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				if err := cs.ah.DeleteOrg(ctx, orgs[0].ID); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
			},
		},
		{
			name: "test delete org by name",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				orgs, err := getOrgs(ctx, cs)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				if err := cs.ah.DeleteOrg(ctx, orgs[0].Name); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
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
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			// create related entries
			// add new entries related to org when needed to properly test
			// that all will be removed alongside the org
			if _, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"}); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if _, err := cs.ah.AddOrgMember(ctx, "org01", "user01", types.MemberRoleMember); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if _, err := cs.ah.CreateOrgInvitation(ctx, &action.CreateOrgInvitationRequest{OrganizationRef: "org01", UserRef: "user01", Role: types.MemberRoleMember}); err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			go func() { _ = cs.Run(ctx) }()

			tt.f(ctx, t, cs)

			orgs, err := getOrgs(ctx, cs)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if len(orgs) != 0 {
				t.Fatalf("expected 0 orgs, got %d orgs", len(orgs))
			}
		})
	}
}

func TestOrgInvitation(t *testing.T) {
	t.Parallel()

	log := testutil.NewLogger(t)

	tests := []struct {
		name string
		f    func(ctx context.Context, t *testing.T, cs *Configstore)
	}{
		{
			name: "test create org invitation",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				setupUsers(t, ctx, cs)
				users, err := getUsers(ctx, cs)
				if err != nil {
					t.Fatalf("err: %v", err)
				}
				userOwner := users[0]
				userInvitation := users[1]

				setupOrgs(t, ctx, cs, userOwner.ID)
				orgs, err := getOrgs(ctx, cs)
				if err != nil {
					t.Fatalf("err: %v", err)
				}
				org := orgs[0]

				rs := &action.CreateOrgInvitationRequest{
					UserRef:         userInvitation.ID,
					OrganizationRef: org.ID,
					Role:            types.MemberRoleMember,
				}
				_, err = cs.ah.CreateOrgInvitation(ctx, rs)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				fmt.Println("err:", err)
			},
		},
		{
			name: "test user org invitation creation with already existing invitation",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				setupUsers(t, ctx, cs)
				users, err := getUsers(ctx, cs)
				if err != nil {
					t.Fatalf("err: %v", err)
				}

				userOwner := users[0]
				userInvitation := users[1]

				setupOrgs(t, ctx, cs, userOwner.ID)
				orgs, err := getOrgs(ctx, cs)
				if err != nil {
					t.Fatalf("err: %v", err)
				}
				if len(users) == 0 {
					t.Fatalf("err: users empty")
				}
				org := orgs[0]

				rs := &action.CreateOrgInvitationRequest{
					UserRef:         userInvitation.ID,
					OrganizationRef: org.ID,
					Role:            types.MemberRoleMember,
				}
				_, err = cs.ah.CreateOrgInvitation(ctx, rs)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				expectedError := util.NewAPIError(util.ErrBadRequest, errors.Errorf("invitation already exists"))
				_, err = cs.ah.CreateOrgInvitation(ctx, rs)
				if err.Error() != expectedError.Error() {
					t.Fatalf("expected err: %v, got err: %v", expectedError.Error(), err.Error())
				}
			},
		},
		{
			name: "test org deletion with existing org invitations",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				setupUsers(t, ctx, cs)
				users, err := getUsers(ctx, cs)
				if err != nil {
					t.Fatalf("err: %v", err)
				}
				userOwner := users[0]
				userInvitation := users[1]

				setupOrgs(t, ctx, cs, userOwner.ID)
				orgs, err := getOrgs(ctx, cs)
				if err != nil {
					t.Fatalf("err: %v", err)
				}
				org := orgs[0]

				rs := &action.CreateOrgInvitationRequest{
					UserRef:         userInvitation.ID,
					OrganizationRef: org.ID,
					Role:            types.MemberRoleMember,
				}
				_, err = cs.ah.CreateOrgInvitation(ctx, rs)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				err = cs.ah.DeleteOrg(ctx, org.ID)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				orgInvitations, err := cs.ah.GetUserOrgInvitations(ctx, userInvitation.ID)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if len(orgInvitations) != 0 {
					t.Fatalf("expected 0 orgInvitations, got %d orgInvitations", len(orgInvitations))
				}

			},
		},
		{
			name: "test user deletion with existing org invitations",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				setupUsers(t, ctx, cs)
				users, err := getUsers(ctx, cs)
				if err != nil {
					t.Fatalf("err: %v", err)
				}
				userOwner := users[0]
				userInvitation := users[1]

				setupOrgs(t, ctx, cs, userOwner.ID)
				orgs, err := getOrgs(ctx, cs)
				if err != nil {
					t.Fatalf("err: %v", err)
				}
				org := orgs[0]

				rs := &action.CreateOrgInvitationRequest{
					UserRef:         userInvitation.ID,
					OrganizationRef: org.ID,
					Role:            types.MemberRoleMember,
				}
				_, err = cs.ah.CreateOrgInvitation(ctx, rs)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				err = cs.ah.DeleteUser(ctx, userInvitation.ID)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				orgInvitations, err := cs.ah.GetOrgInvitations(ctx, org.ID)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if len(orgInvitations) != 0 {
					t.Fatalf("expected 0 orgInvitations, got %d orgInvitations", len(orgInvitations))
				}
			},
		},
		{
			name: "test add org member with an existing org invitation",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				setupUsers(t, ctx, cs)
				users, err := getUsers(ctx, cs)
				if err != nil {
					t.Fatalf("err: %v", err)
				}
				userOwner := users[0]
				userInvitation := users[1]

				setupOrgs(t, ctx, cs, userOwner.ID)
				orgs, err := getOrgs(ctx, cs)
				if err != nil {
					t.Fatalf("err: %v", err)
				}
				org := orgs[0]

				rs := &action.CreateOrgInvitationRequest{
					UserRef:         userInvitation.ID,
					OrganizationRef: org.ID,
					Role:            types.MemberRoleMember,
				}
				_, err = cs.ah.CreateOrgInvitation(ctx, rs)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				_, err = cs.ah.AddOrgMember(ctx, org.ID, userInvitation.ID, types.MemberRoleMember)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				orgInvitations, err := cs.ah.GetOrgInvitations(ctx, org.ID)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if len(orgInvitations) != 0 {
					t.Fatalf("expected 0 orgInvitations, got %d orgInvitations", len(orgInvitations))
				}
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
