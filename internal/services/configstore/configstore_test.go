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

	"github.com/sorintlab/agola/internal/db"
	"github.com/sorintlab/agola/internal/services/config"
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

func setupConfigstore(t *testing.T, ctx context.Context, dir string) (*ConfigStore, *testutil.TestEmbeddedEtcd) {
	etcdDir, err := ioutil.TempDir(dir, "etcd")
	tetcd := setupEtcd(t, etcdDir)

	listenAddress, port, err := testutil.GetFreePort(true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	ltsDir, err := ioutil.TempDir(dir, "lts")
	csDir, err := ioutil.TempDir(dir, "cs")

	baseConfig := config.ConfigStore{
		Etcd: config.Etcd{
			Endpoints: tetcd.Endpoint,
		},
		LTS: config.LTS{
			Type: config.LTSTypePosix,
			Path: ltsDir,
		},
		Web: config.Web{},
	}
	csConfig := baseConfig
	csConfig.DataDir = csDir
	csConfig.Web.ListenAddress = net.JoinHostPort(listenAddress, port)

	cs, err := NewConfigStore(ctx, &csConfig)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	return cs, tetcd
}

func getProjects(cs *ConfigStore) ([]*types.Project, error) {
	var projects []*types.Project
	err := cs.readDB.Do(func(tx *db.Tx) error {
		var err error
		projects, err = cs.readDB.GetAllProjects(tx)
		return err
	})
	return projects, err
}

func getUsers(cs *ConfigStore) ([]*types.User, error) {
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

	ltsDir, err := ioutil.TempDir(dir, "lts")
	csDir1, err := ioutil.TempDir(dir, "cs1")
	csDir2, err := ioutil.TempDir(dir, "cs2")
	csDir3, err := ioutil.TempDir(dir, "cs3")

	baseConfig := config.ConfigStore{
		Etcd: config.Etcd{
			Endpoints: tetcd.Endpoint,
		},
		LTS: config.LTS{
			Type: config.LTSTypePosix,
			Path: ltsDir,
		},
		Web: config.Web{},
	}
	cs1Config := baseConfig
	cs1Config.DataDir = csDir1
	cs1Config.Web.ListenAddress = net.JoinHostPort(listenAddress1, port1)

	cs2Config := baseConfig
	cs2Config.DataDir = csDir2
	cs2Config.Web.ListenAddress = net.JoinHostPort(listenAddress2, port2)

	cs1, err := NewConfigStore(ctx, &cs1Config)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	cs2, err := NewConfigStore(ctx, &cs2Config)
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
	go func() {
		if err := cs2.Run(ctx2); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()

	time.Sleep(1 * time.Second)

	for i := 0; i < 10; i++ {
		if _, err := cs1.ch.CreateUser(ctx, &types.User{UserName: fmt.Sprintf("user%d", i)}); err != nil {
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
		if _, err := cs1.ch.CreateUser(ctx, &types.User{UserName: fmt.Sprintf("user%d", i)}); err != nil {
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
	cs2, err = NewConfigStore(ctx, &cs2Config)
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
	cs3, err := NewConfigStore(ctx, &cs3Config)
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
		_, err := cs.ch.CreateUser(ctx, &types.User{UserName: "user01"})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})

	// TODO(sgotti) change the sleep with a real check that user is in readdb
	time.Sleep(2 * time.Second)

	t.Run("create duplicated user", func(t *testing.T) {
		expectedErr := fmt.Sprintf("bad request: user with name %q already exists", "user01")
		_, err := cs.ch.CreateUser(ctx, &types.User{UserName: "user01"})
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
			go cs.ch.CreateUser(ctx, &types.User{UserName: "user02"})
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

	user, err := cs.ch.CreateUser(ctx, &types.User{UserName: "user01"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	org, err := cs.ch.CreateOrg(ctx, &types.Organization{Name: "org01"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// TODO(sgotti) change the sleep with a real check that user is in readdb
	time.Sleep(2 * time.Second)

	t.Run("create a project in user root project group", func(t *testing.T) {
		_, err := cs.ch.CreateProject(ctx, &types.Project{Name: "project01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.UserName)}})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("create a project in org root project group", func(t *testing.T) {
		_, err := cs.ch.CreateProject(ctx, &types.Project{Name: "project01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("org", org.Name)}})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("create a projectgroup in user root project group", func(t *testing.T) {
		_, err := cs.ch.CreateProjectGroup(ctx, &types.ProjectGroup{Name: "projectgroup01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.UserName)}})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("create a projectgroup in org root project group", func(t *testing.T) {
		_, err := cs.ch.CreateProjectGroup(ctx, &types.ProjectGroup{Name: "projectgroup01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("org", org.Name)}})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("create a project in user non root project group with same name as a root project", func(t *testing.T) {
		_, err := cs.ch.CreateProject(ctx, &types.Project{Name: "project01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.UserName, "projectgroup01")}})
		if err != nil {
			t.Fatalf("unexpected err: %+#v", err)
		}
	})
	t.Run("create a project in org non root project group with same name as a root project", func(t *testing.T) {
		_, err := cs.ch.CreateProject(ctx, &types.Project{Name: "project01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("org", org.Name, "projectgroup01")}})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})

	t.Run("create duplicated project in user root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := fmt.Sprintf("bad request: project with name %q, path %q already exists", projectName, path.Join("user", user.UserName, projectName))
		_, err := cs.ch.CreateProject(ctx, &types.Project{Name: projectName, Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.UserName)}})
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("create duplicated project in org root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := fmt.Sprintf("bad request: project with name %q, path %q already exists", projectName, path.Join("org", org.Name, projectName))
		_, err := cs.ch.CreateProject(ctx, &types.Project{Name: projectName, Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("org", org.Name)}})
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})

	t.Run("create duplicated project in user non root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := fmt.Sprintf("bad request: project with name %q, path %q already exists", projectName, path.Join("user", user.UserName, "projectgroup01", projectName))
		_, err := cs.ch.CreateProject(ctx, &types.Project{Name: projectName, Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.UserName, "projectgroup01")}})
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("create duplicated project in org non root project group", func(t *testing.T) {
		projectName := "project01"
		expectedErr := fmt.Sprintf("bad request: project with name %q, path %q already exists", projectName, path.Join("org", org.Name, "projectgroup01", projectName))
		_, err := cs.ch.CreateProject(ctx, &types.Project{Name: projectName, Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("org", org.Name, "projectgroup01")}})
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})

	t.Run("create project in unexistent project group", func(t *testing.T) {
		expectedErr := `bad request: project group with id "unexistentid" doesn't exist`
		_, err := cs.ch.CreateProject(ctx, &types.Project{Name: "project01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: "unexistentid"}})
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("create project without parent id specified", func(t *testing.T) {
		expectedErr := "bad request: project parent id required"
		_, err := cs.ch.CreateProject(ctx, &types.Project{Name: "project01"})
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
			go cs.ch.CreateProject(ctx, &types.Project{Name: "project02", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.UserName)}})
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
