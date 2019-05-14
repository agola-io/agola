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
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/config"
	action "github.com/sorintlab/agola/internal/services/configstore/action"
	"github.com/sorintlab/agola/internal/services/types"
	"github.com/sorintlab/agola/internal/testutil"
	"github.com/sorintlab/agola/internal/util"
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
		tetcd.Kill()
	}
}

func setupConfigstore(t *testing.T, ctx context.Context, dir string) (*Configstore, *testutil.TestEmbeddedEtcd) {
	etcdDir, err := ioutil.TempDir(dir, "etcd")
	tetcd := setupEtcd(t, etcdDir)

	listenAddress, port, err := testutil.GetFreePort(true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	ostDir, err := ioutil.TempDir(dir, "ost")
	csDir, err := ioutil.TempDir(dir, "cs")

	baseConfig := config.Configstore{
		Etcd: config.Etcd{
			Endpoints: tetcd.Endpoint,
		},
		ObjectStorage: config.ObjectStorage{
			Type: config.ObjectStorageTypePosix,
			Path: ostDir,
		},
		Web: config.Web{},
	}
	csConfig := baseConfig
	csConfig.DataDir = csDir
	csConfig.Web.ListenAddress = net.JoinHostPort(listenAddress, port)

	cs, err := NewConfigstore(ctx, &csConfig)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	return cs, tetcd
}

func getProjects(cs *Configstore) ([]*types.Project, error) {
	var projects []*types.Project
	err := cs.readDB.Do(func(tx *db.Tx) error {
		var err error
		projects, err = cs.readDB.GetAllProjects(tx)
		return err
	})
	return projects, err
}

func getUsers(cs *Configstore) ([]*types.User, error) {
	var users []*types.User
	err := cs.readDB.Do(func(tx *db.Tx) error {
		var err error
		users, err = cs.readDB.GetUsers(tx, "", 0, true)
		return err
	})
	return users, err
}

func TestResync(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	etcdDir, err := ioutil.TempDir(dir, "etcd")
	tetcd := setupEtcd(t, etcdDir)
	defer shutdownEtcd(tetcd)

	listenAddress1, port1, err := testutil.GetFreePort(true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	listenAddress2, port2, err := testutil.GetFreePort(true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	listenAddress3, port3, err := testutil.GetFreePort(true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	ctx := context.Background()

	ostDir, err := ioutil.TempDir(dir, "ost")
	csDir1, err := ioutil.TempDir(dir, "cs1")
	csDir2, err := ioutil.TempDir(dir, "cs2")
	csDir3, err := ioutil.TempDir(dir, "cs3")

	baseConfig := config.Configstore{
		Etcd: config.Etcd{
			Endpoints: tetcd.Endpoint,
		},
		ObjectStorage: config.ObjectStorage{
			Type: config.ObjectStorageTypePosix,
			Path: ostDir,
		},
		Web: config.Web{},
	}
	cs1Config := baseConfig
	cs1Config.DataDir = csDir1
	cs1Config.Web.ListenAddress = net.JoinHostPort(listenAddress1, port1)

	cs2Config := baseConfig
	cs2Config.DataDir = csDir2
	cs2Config.Web.ListenAddress = net.JoinHostPort(listenAddress2, port2)

	cs1, err := NewConfigstore(ctx, &cs1Config)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	cs2, err := NewConfigstore(ctx, &cs2Config)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	ctx1 := context.Background()
	ctx2, cancel2 := context.WithCancel(context.Background())

	t.Logf("starting cs1")
	go func() {
		if err := cs1.Run(ctx1); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()
	t.Logf("starting cs2")
	go func() {
		if err := cs2.Run(ctx2); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()

	time.Sleep(1 * time.Second)

	for i := 0; i < 10; i++ {
		if _, err := cs1.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: fmt.Sprintf("user%d", i)}); err != nil {
			t.Fatalf("err: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	time.Sleep(5 * time.Second)

	// stop cs2
	log.Infof("stopping cs2")
	cancel2()

	// Do some more changes
	for i := 11; i < 20; i++ {
		if _, err := cs1.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: fmt.Sprintf("user%d", i)}); err != nil {
			t.Fatalf("err: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	time.Sleep(5 * time.Second)

	// compact etcd
	if err := tetcd.Compact(); err != nil {
		t.Fatalf("err: %v", err)
	}

	// start cs2
	// it should resync from wals since the etcd revision as been compacted
	cs2, err = NewConfigstore(ctx, &cs2Config)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	log.Infof("starting cs2")
	ctx2 = context.Background()
	go cs2.Run(ctx2)

	time.Sleep(5 * time.Second)

	users1, err := getUsers(cs1)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	users2, err := getUsers(cs2)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !compareUsers(users1, users2) {
		t.Logf("len(users1): %d", len(users1))
		t.Logf("len(users2): %d", len(users2))
		t.Logf("users1: %s", util.Dump(users1))
		t.Logf("users2: %s", util.Dump(users2))
		t.Fatalf("users are different between the two readdbs")
	}

	// start cs3, since it's a new instance it should do a full resync
	cs3Config := baseConfig
	cs3Config.DataDir = csDir3
	cs3Config.Web.ListenAddress = net.JoinHostPort(listenAddress3, port3)

	log.Infof("starting cs3")
	cs3, err := NewConfigstore(ctx, &cs3Config)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	ctx3 := context.Background()
	go cs3.Run(ctx3)

	time.Sleep(5 * time.Second)

	users1, err = getUsers(cs1)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	users3, err := getUsers(cs3)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !compareUsers(users1, users3) {
		t.Logf("len(users1): %d", len(users1))
		t.Logf("len(users3): %d", len(users3))
		t.Logf("users1: %s", util.Dump(users1))
		t.Logf("users3: %s", util.Dump(users3))
		t.Fatalf("users are different between the two readdbs")
	}
}

func compareUsers(u1, u2 []*types.User) bool {
	u1ids := map[string]struct{}{}
	u2ids := map[string]struct{}{}

	for _, u := range u1 {
		u1ids[u.ID] = struct{}{}
	}
	for _, u := range u2 {
		u2ids[u.ID] = struct{}{}
	}

	return reflect.DeepEqual(u1ids, u2ids)
}

func TestUser(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()

	cs, tetcd := setupConfigstore(t, ctx, dir)
	defer shutdownEtcd(tetcd)

	t.Logf("starting cs")
	go func() {
		if err := cs.Run(ctx); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()

	// TODO(sgotti) change the sleep with a real check that all is ready
	time.Sleep(2 * time.Second)

	t.Run("create user", func(t *testing.T) {
		_, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})

	// TODO(sgotti) change the sleep with a real check that user is in readdb
	time.Sleep(2 * time.Second)

	t.Run("create duplicated user", func(t *testing.T) {
		expectedErr := fmt.Sprintf("user with name %q already exists", "user01")
		_, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
		if err == nil {
			t.Fatalf("expected error %v, got nil err", expectedErr)
		}
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("concurrent user with same name creation", func(t *testing.T) {
		prevUsers, err := getUsers(cs)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		wg := sync.WaitGroup{}
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user02"})
			wg.Done()
		}
		wg.Wait()

		time.Sleep(5 * time.Second)

		users, err := getUsers(cs)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		if len(users) != len(prevUsers)+1 {
			t.Fatalf("expected %d users, got %d", len(prevUsers)+1, len(users))
		}
	})
}

func TestProjectGroupsAndProjects(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()

	cs, tetcd := setupConfigstore(t, ctx, dir)
	defer shutdownEtcd(tetcd)

	t.Logf("starting cs")
	go func() {
		if err := cs.Run(ctx); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()

	// TODO(sgotti) change the sleep with a real check that all is ready
	time.Sleep(2 * time.Second)

	user, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	org, err := cs.ah.CreateOrg(ctx, &types.Organization{Name: "org01", Visibility: types.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// TODO(sgotti) change the sleep with a real check that user is in readdb
	time.Sleep(2 * time.Second)

	t.Run("create a project in user root project group", func(t *testing.T) {
		_, err := cs.ah.CreateProject(ctx, &types.Project{Name: "project01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("create a project in org root project group", func(t *testing.T) {
		_, err := cs.ah.CreateProject(ctx, &types.Project{Name: "project01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("create a projectgroup in user root project group", func(t *testing.T) {
		_, err := cs.ah.CreateProjectGroup(ctx, &types.ProjectGroup{Name: "projectgroup01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("create a projectgroup in org root project group", func(t *testing.T) {
		_, err := cs.ah.CreateProjectGroup(ctx, &types.ProjectGroup{Name: "projectgroup01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("create a project in user non root project group with same name as a root project", func(t *testing.T) {
		_, err := cs.ah.CreateProject(ctx, &types.Project{Name: "project01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("create a project in org non root project group with same name as a root project", func(t *testing.T) {
		_, err := cs.ah.CreateProject(ctx, &types.Project{Name: "project01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("org", org.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})

	t.Run("create duplicated project in user root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := fmt.Sprintf("project with name %q, path %q already exists", projectName, path.Join("user", user.Name, projectName))
		_, err := cs.ah.CreateProject(ctx, &types.Project{Name: projectName, Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("create duplicated project in org root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := fmt.Sprintf("project with name %q, path %q already exists", projectName, path.Join("org", org.Name, projectName))
		_, err := cs.ah.CreateProject(ctx, &types.Project{Name: projectName, Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})

	t.Run("create duplicated project in user non root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := fmt.Sprintf("project with name %q, path %q already exists", projectName, path.Join("user", user.Name, "projectgroup01", projectName))
		_, err := cs.ah.CreateProject(ctx, &types.Project{Name: projectName, Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("create duplicated project in org non root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := fmt.Sprintf("project with name %q, path %q already exists", projectName, path.Join("org", org.Name, "projectgroup01", projectName))
		_, err := cs.ah.CreateProject(ctx, &types.Project{Name: projectName, Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("org", org.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})

	t.Run("create project in unexistent project group", func(t *testing.T) {
		expectedErr := `project group with id "unexistentid" doesn't exist`
		_, err := cs.ah.CreateProject(ctx, &types.Project{Name: "project01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: "unexistentid"}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("create project without parent id specified", func(t *testing.T) {
		expectedErr := "project parent id required"
		_, err := cs.ah.CreateProject(ctx, &types.Project{Name: "project01", Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})

	t.Run("concurrent project with same name creation", func(t *testing.T) {
		prevProjects, err := getProjects(cs)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		wg := sync.WaitGroup{}
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go cs.ah.CreateProject(ctx, &types.Project{Name: "project02", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
			wg.Done()
		}
		wg.Wait()

		time.Sleep(1 * time.Second)

		projects, err := getProjects(cs)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		if len(projects) != len(prevProjects)+1 {
			t.Fatalf("expected %d projects, got %d", len(prevProjects)+1, len(projects))
		}
	})
}

func TestProjectGroupDelete(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()

	cs, tetcd := setupConfigstore(t, ctx, dir)
	defer shutdownEtcd(tetcd)

	t.Logf("starting cs")
	go func() {
		if err := cs.Run(ctx); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()

	// TODO(sgotti) change the sleep with a real check that all is ready
	time.Sleep(2 * time.Second)

	//user, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
	//if err != nil {
	//	t.Fatalf("unexpected err: %v", err)
	//}
	org, err := cs.ah.CreateOrg(ctx, &types.Organization{Name: "org01", Visibility: types.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// TODO(sgotti) change the sleep with a real check that user is in readdb
	time.Sleep(2 * time.Second)

	// create a projectgroup in org root project group
	pg01, err := cs.ah.CreateProjectGroup(ctx, &types.ProjectGroup{Name: "projectgroup01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	//create a child projectgroup in org root project group
	spg01, err := cs.ah.CreateProjectGroup(ctx, &types.ProjectGroup{Name: "subprojectgroup01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: pg01.ID}, Visibility: types.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// create a project inside child projectgroup
	project, err := cs.ah.CreateProject(ctx, &types.Project{Name: "project01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: spg01.ID}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// create project secret
	_, err = cs.ah.CreateSecret(ctx, &types.Secret{Name: "secret01", Parent: types.Parent{Type: types.ConfigTypeProject, ID: project.ID}, Type: types.SecretTypeInternal, Data: map[string]string{"secret01": "secretvar01"}})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	// create project variable
	_, err = cs.ah.CreateVariable(ctx, &types.Variable{Name: "variable01", Parent: types.Parent{Type: types.ConfigTypeProject, ID: project.ID}, Values: []types.VariableValue{{SecretName: "secret01", SecretVar: "secretvar01"}}})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// delete root projectgroup
	if err = cs.ah.DeleteProjectGroup(ctx, pg01.ID); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// recreate the same hierarchj using the paths
	pg01, err = cs.ah.CreateProjectGroup(ctx, &types.ProjectGroup{Name: "projectgroup01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("org", org.Name)}, Visibility: types.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	spg01, err = cs.ah.CreateProjectGroup(ctx, &types.ProjectGroup{Name: "subprojectgroup01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("org", org.Name, pg01.Name)}, Visibility: types.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	project, err = cs.ah.CreateProject(ctx, &types.Project{Name: "project01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("org", org.Name, pg01.Name, spg01.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	secret, err := cs.ah.CreateSecret(ctx, &types.Secret{Name: "secret01", Parent: types.Parent{Type: types.ConfigTypeProject, ID: path.Join("org", org.Name, pg01.Name, spg01.Name, project.Name)}, Type: types.SecretTypeInternal, Data: map[string]string{"secret01": "secretvar01"}})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	variable, err := cs.ah.CreateVariable(ctx, &types.Variable{Name: "variable01", Parent: types.Parent{Type: types.ConfigTypeProject, ID: path.Join("org", org.Name, pg01.Name, spg01.Name, project.Name)}, Values: []types.VariableValue{{SecretName: "secret01", SecretVar: "secretvar01"}}})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// Get by projectgroup id
	projects, err := cs.ah.GetProjectGroupProjects(ctx, spg01.ID)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(projects, []*types.Project{project}); diff != "" {
		t.Error(diff)
	}

	// Get by projectgroup path
	projects, err = cs.ah.GetProjectGroupProjects(ctx, path.Join("org", org.Name, pg01.Name, spg01.Name))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(projects, []*types.Project{project}); diff != "" {
		t.Error(diff)
	}

	secrets, err := cs.ah.GetSecrets(ctx, types.ConfigTypeProject, project.ID, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(secrets, []*types.Secret{secret}); diff != "" {
		t.Error(diff)
	}

	secrets, err = cs.ah.GetSecrets(ctx, types.ConfigTypeProject, path.Join("org", org.Name, pg01.Name, spg01.Name, project.Name), false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(secrets, []*types.Secret{secret}); diff != "" {
		t.Error(diff)
	}

	variables, err := cs.ah.GetVariables(ctx, types.ConfigTypeProject, project.ID, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(variables, []*types.Variable{variable}); diff != "" {
		t.Error(diff)
	}

	variables, err = cs.ah.GetVariables(ctx, types.ConfigTypeProject, path.Join("org", org.Name, pg01.Name, spg01.Name, project.Name), false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if diff := cmp.Diff(variables, []*types.Variable{variable}); diff != "" {
		t.Error(diff)
	}
}

func TestOrgMembers(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()

	cs, tetcd := setupConfigstore(t, ctx, dir)
	defer shutdownEtcd(tetcd)

	t.Logf("starting cs")
	go func() {
		if err := cs.Run(ctx); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()

	// TODO(sgotti) change the sleep with a real check that all is ready
	time.Sleep(2 * time.Second)

	user, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	org, err := cs.ah.CreateOrg(ctx, &types.Organization{Name: "org01", Visibility: types.VisibilityPublic, CreatorUserID: user.ID})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// TODO(sgotti) change the sleep with a real check that all is ready
	time.Sleep(2 * time.Second)

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
		if diff := cmp.Diff(res, expectedResponse); diff != "" {
			t.Error(diff)
		}
	})

	orgs := []*types.Organization{}
	for i := 0; i < 10; i++ {
		org, err := cs.ah.CreateOrg(ctx, &types.Organization{Name: fmt.Sprintf("org%d", i), Visibility: types.VisibilityPublic, CreatorUserID: user.ID})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		orgs = append(orgs, org)
		time.Sleep(200 * time.Millisecond)
	}

	for i := 0; i < 5; i++ {
		if err := cs.ah.DeleteOrg(ctx, fmt.Sprintf("org%d", i)); err != nil {
			t.Fatalf("err: %v", err)
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
		if diff := cmp.Diff(res, expectedResponse); diff != "" {
			t.Error(diff)
		}
	})

	// TODO(sgotti) change the sleep with a real check that user is in readdb
	time.Sleep(2 * time.Second)

}
