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
	"io/ioutil"
	"net"
	"os"
	"path"
	"reflect"
	"sync"
	"testing"
	"time"

	"agola.io/agola/internal/db"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/configstore/action"
	"agola.io/agola/internal/testutil"
	"agola.io/agola/internal/util"
	"agola.io/agola/services/configstore/types"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
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

func setupConfigstore(ctx context.Context, t *testing.T, logger *zap.Logger, dir string) (*Configstore, *testutil.TestEmbeddedEtcd) {
	etcdDir, err := ioutil.TempDir(dir, "etcd")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	tetcd := setupEtcd(t, logger, etcdDir)

	listenAddress, port, err := testutil.GetFreePort(true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	ostDir, err := ioutil.TempDir(dir, "ost")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	csDir, err := ioutil.TempDir(dir, "cs")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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

	cs, err := NewConfigstore(ctx, logger, &csConfig)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	return cs, tetcd
}

func getProjects(ctx context.Context, cs *Configstore) ([]*types.Project, error) {
	var projects []*types.Project
	err := cs.readDB.Do(ctx, func(tx *db.Tx) error {
		var err error
		projects, err = cs.readDB.GetAllProjects(tx)
		return err
	})
	return projects, err
}

func getUsers(ctx context.Context, cs *Configstore) ([]*types.User, error) {
	var users []*types.User
	err := cs.readDB.Do(ctx, func(tx *db.Tx) error {
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

	logger := zaptest.NewLogger(t, zaptest.Level(zap.InfoLevel))

	etcdDir, err := ioutil.TempDir(dir, "etcd")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	tetcd := setupEtcd(t, logger, etcdDir)
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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	csDir1, err := ioutil.TempDir(dir, "cs1")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	csDir2, err := ioutil.TempDir(dir, "cs2")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	csDir3, err := ioutil.TempDir(dir, "cs3")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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

	cs1, err := NewConfigstore(ctx, logger.With(zap.String("name", "cs1")), &cs1Config)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	cs2, err := NewConfigstore(ctx, logger.With(zap.String("name", "cs2")), &cs2Config)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	ctx1 := context.Background()
	ctx2, cancel2 := context.WithCancel(context.Background())

	t.Logf("starting cs1")
	go func() { _ = cs1.Run(ctx1) }()
	t.Logf("starting cs2")
	go func() { _ = cs2.Run(ctx2) }()

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
	for i := 10; i < 20; i++ {
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
	cs2, err = NewConfigstore(ctx, logger.With(zap.String("name", "cs2")), &cs2Config)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	log.Infof("starting cs2")
	ctx2 = context.Background()
	go func() { _ = cs2.Run(ctx2) }()

	time.Sleep(5 * time.Second)

	users1, err := getUsers(ctx, cs1)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(users1) != 20 {
		t.Logf("users1: %s", util.Dump(users1))
		t.Fatalf("expected %d users, got %d users", 20, len(users1))
	}

	users2, err := getUsers(ctx, cs2)
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

	cs3, err := NewConfigstore(ctx, logger.With(zap.String("name", "cs3")), &cs3Config)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	log.Infof("starting cs3")
	ctx3 := context.Background()
	go func() { _ = cs3.Run(ctx3) }()

	time.Sleep(5 * time.Second)

	users3, err := getUsers(ctx, cs3)
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

func TestExportImport(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	logger := zaptest.NewLogger(t, zaptest.Level(zap.InfoLevel))

	etcdDir, err := ioutil.TempDir(dir, "etcd")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	tetcd := setupEtcd(t, logger, etcdDir)
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
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	csDir1, err := ioutil.TempDir(dir, "cs1")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	csDir2, err := ioutil.TempDir(dir, "cs2")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	csDir3, err := ioutil.TempDir(dir, "cs3")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

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

	cs3Config := baseConfig
	cs3Config.DataDir = csDir3
	cs3Config.Web.ListenAddress = net.JoinHostPort(listenAddress3, port3)

	cs1, err := NewConfigstore(ctx, logger.With(zap.String("name", "cs1")), &cs1Config)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	cs2, err := NewConfigstore(ctx, logger.With(zap.String("name", "cs2")), &cs2Config)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	cs3, err := NewConfigstore(ctx, logger.With(zap.String("name", "cs3")), &cs3Config)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	ctx1 := context.Background()
	ctx2, cancel2 := context.WithCancel(context.Background())
	ctx3, cancel3 := context.WithCancel(context.Background())

	t.Logf("starting cs1")
	go func() { _ = cs1.Run(ctx1) }()
	t.Logf("starting cs2")
	go func() { _ = cs2.Run(ctx2) }()
	t.Logf("starting cs3")
	go func() { _ = cs3.Run(ctx3) }()

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
	// stop cs3
	log.Infof("stopping cs3")
	cancel3()

	// Do some more changes
	for i := 10; i < 20; i++ {
		if _, err := cs1.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: fmt.Sprintf("user%d", i)}); err != nil {
			t.Fatalf("err: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	time.Sleep(5 * time.Second)

	users1, err := getUsers(ctx, cs1)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(users1) != 20 {
		t.Logf("users1: %s", util.Dump(users1))
		t.Fatalf("expected %d users, got %d users", 20, len(users1))
	}

	var export bytes.Buffer
	if err := cs1.ah.Export(ctx, &export); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if err := cs1.ah.MaintenanceMode(ctx, true); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	time.Sleep(5 * time.Second)

	if err := cs1.ah.Import(ctx, &export); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if err := cs1.ah.MaintenanceMode(ctx, false); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	time.Sleep(5 * time.Second)

	newUsers1, err := getUsers(ctx, cs1)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !compareUsers(users1, newUsers1) {
		t.Logf("len(users1): %d", len(users1))
		t.Logf("len(newUsers1): %d", len(newUsers1))
		t.Logf("users1: %s", util.Dump(users1))
		t.Logf("newUsers1: %s", util.Dump(newUsers1))
		t.Fatalf("users are different between the two readdbs")
	}

	// start cs2
	// it should do a full resync since we have imported new data and there's now wal in etcd
	cs2, err = NewConfigstore(ctx, logger.With(zap.String("name", "cs2")), &cs2Config)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	log.Infof("starting cs2")
	ctx2 = context.Background()
	go func() { _ = cs2.Run(ctx2) }()

	time.Sleep(5 * time.Second)

	users2, err := getUsers(ctx, cs2)
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

	// Do some more changes
	for i := 20; i < 30; i++ {
		if _, err := cs1.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: fmt.Sprintf("user%d", i)}); err != nil {
			t.Fatalf("err: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	time.Sleep(5 * time.Second)

	users1, err = getUsers(ctx, cs1)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(users1) != 30 {
		t.Logf("users1: %s", util.Dump(users1))
		t.Fatalf("expected %d users, got %d users", 30, len(users1))
	}

	// start cs3
	// it should do a full resync since we have imported new data and there're some wals with a different epoch
	cs3, err = NewConfigstore(ctx, logger.With(zap.String("name", "cs3")), &cs3Config)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	log.Infof("starting cs3")
	ctx3 = context.Background()
	go func() { _ = cs3.Run(ctx3) }()

	time.Sleep(5 * time.Second)

	users3, err := getUsers(ctx, cs3)
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
	logger := zaptest.NewLogger(t, zaptest.Level(zap.InfoLevel))

	cs, tetcd := setupConfigstore(ctx, t, logger, dir)
	defer shutdownEtcd(tetcd)

	t.Logf("starting cs")
	go func() {
		_ = cs.Run(ctx)
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
		prevUsers, err := getUsers(ctx, cs)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		wg := sync.WaitGroup{}
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() { _, _ = cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user02"}) }()
			wg.Done()
		}
		wg.Wait()

		time.Sleep(5 * time.Second)

		users, err := getUsers(ctx, cs)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		if len(users) != len(prevUsers)+1 {
			t.Fatalf("expected %d users, got %d", len(prevUsers)+1, len(users))
		}
	})
}

func TestProjectGroupsAndProjectsCreate(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()
	logger := zaptest.NewLogger(t, zaptest.Level(zap.InfoLevel))

	cs, tetcd := setupConfigstore(ctx, t, logger, dir)
	defer shutdownEtcd(tetcd)

	t.Logf("starting cs")
	go func() {
		_ = cs.Run(ctx)
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
		prevProjects, err := getProjects(ctx, cs)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		wg := sync.WaitGroup{}
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				_, _ = cs.ah.CreateProject(ctx, &types.Project{Name: "project02", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual})
			}()
			wg.Done()
		}
		wg.Wait()

		time.Sleep(1 * time.Second)

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
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()
	logger := zaptest.NewLogger(t, zaptest.Level(zap.InfoLevel))

	cs, tetcd := setupConfigstore(ctx, t, logger, dir)
	defer shutdownEtcd(tetcd)

	t.Logf("starting cs")
	go func() {
		_ = cs.Run(ctx)
	}()

	// TODO(sgotti) change the sleep with a real check that all is ready
	time.Sleep(2 * time.Second)

	user, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// TODO(sgotti) change the sleep with a real check that user is in readdb
	time.Sleep(2 * time.Second)

	_, err = cs.ah.CreateProjectGroup(ctx, &types.ProjectGroup{Name: "projectgroup01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	p01 := &types.Project{Name: "project01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual}
	_, err = cs.ah.CreateProject(ctx, p01)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	p02 := &types.Project{Name: "project01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual}
	_, err = cs.ah.CreateProject(ctx, p02)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	p03 := &types.Project{Name: "project02", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name, "projectgroup01")}, Visibility: types.VisibilityPublic, RemoteRepositoryConfigType: types.RemoteRepositoryConfigTypeManual}
	_, err = cs.ah.CreateProject(ctx, p03)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	t.Run("rename project keeping same parent", func(t *testing.T) {
		projectName := "project02"
		p03.Name = "newproject02"
		_, err := cs.ah.UpdateProject(ctx, &action.UpdateProjectRequest{ProjectRef: path.Join("user", user.Name, "projectgroup01", projectName), Project: p03})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("move project to project group having project with same name", func(t *testing.T) {
		projectName := "project01"
		expectedErr := fmt.Sprintf("project with name %q, path %q already exists", projectName, path.Join("user", user.Name, projectName))
		p02.Parent.ID = path.Join("user", user.Name)
		_, err := cs.ah.UpdateProject(ctx, &action.UpdateProjectRequest{ProjectRef: path.Join("user", user.Name, "projectgroup01", projectName), Project: p02})
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("move project to project group changing name", func(t *testing.T) {
		projectName := "project01"
		p02.Name = "newproject01"
		p02.Parent.ID = path.Join("user", user.Name)
		_, err := cs.ah.UpdateProject(ctx, &action.UpdateProjectRequest{ProjectRef: path.Join("user", user.Name, "projectgroup01", projectName), Project: p02})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
}

func TestProjectGroupUpdate(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()
	logger := zaptest.NewLogger(t, zaptest.Level(zap.InfoLevel))

	cs, tetcd := setupConfigstore(ctx, t, logger, dir)
	defer shutdownEtcd(tetcd)

	t.Logf("starting cs")
	go func() {
		_ = cs.Run(ctx)
	}()

	// TODO(sgotti) change the sleep with a real check that all is ready
	time.Sleep(2 * time.Second)

	user, err := cs.ah.CreateUser(ctx, &action.CreateUserRequest{UserName: "user01"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// TODO(sgotti) change the sleep with a real check that user is in readdb
	time.Sleep(2 * time.Second)

	pg01 := &types.ProjectGroup{Name: "pg01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic}
	pg01, err = cs.ah.CreateProjectGroup(ctx, pg01)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	pg02 := &types.ProjectGroup{Name: "pg02", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic}
	pg02, err = cs.ah.CreateProjectGroup(ctx, pg02)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	pg03 := &types.ProjectGroup{Name: "pg03", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name)}, Visibility: types.VisibilityPublic}
	pg03, err = cs.ah.CreateProjectGroup(ctx, pg03)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	pg04 := &types.ProjectGroup{Name: "pg01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name, "pg01")}, Visibility: types.VisibilityPublic}
	_, err = cs.ah.CreateProjectGroup(ctx, pg04)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	pg05 := &types.ProjectGroup{Name: "pg01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: path.Join("user", user.Name, "pg02")}, Visibility: types.VisibilityPublic}
	pg05, err = cs.ah.CreateProjectGroup(ctx, pg05)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	t.Run("rename project group keeping same parent", func(t *testing.T) {
		projectGroupName := "pg03"
		pg03.Name = "newpg03"
		_, err := cs.ah.UpdateProjectGroup(ctx, &action.UpdateProjectGroupRequest{ProjectGroupRef: path.Join("user", user.Name, projectGroupName), ProjectGroup: pg03})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("move project to project group having project with same name", func(t *testing.T) {
		projectGroupName := "pg01"
		expectedErr := fmt.Sprintf("project group with name %q, path %q already exists", projectGroupName, path.Join("user", user.Name, projectGroupName))
		pg05.Parent.ID = path.Join("user", user.Name)
		_, err := cs.ah.UpdateProjectGroup(ctx, &action.UpdateProjectGroupRequest{ProjectGroupRef: path.Join("user", user.Name, "pg02", projectGroupName), ProjectGroup: pg05})
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("move project group to project group changing name", func(t *testing.T) {
		projectGroupName := "pg01"
		pg05.Name = "newpg01"
		pg05.Parent.ID = path.Join("user", user.Name)
		_, err := cs.ah.UpdateProjectGroup(ctx, &action.UpdateProjectGroupRequest{ProjectGroupRef: path.Join("user", user.Name, "pg02", projectGroupName), ProjectGroup: pg05})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("move project group inside itself", func(t *testing.T) {
		projectGroupName := "pg02"
		expectedErr := "cannot move project group inside itself or child project group"
		pg02.Parent.ID = path.Join("user", user.Name, "pg02")
		_, err := cs.ah.UpdateProjectGroup(ctx, &action.UpdateProjectGroupRequest{ProjectGroupRef: path.Join("user", user.Name, projectGroupName), ProjectGroup: pg02})
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("move project group to child project group", func(t *testing.T) {
		projectGroupName := "pg01"
		expectedErr := "cannot move project group inside itself or child project group"
		pg01.Parent.ID = path.Join("user", user.Name, "pg01", "pg01")
		_, err := cs.ah.UpdateProjectGroup(ctx, &action.UpdateProjectGroupRequest{ProjectGroupRef: path.Join("user", user.Name, projectGroupName), ProjectGroup: pg01})
		if err.Error() != expectedErr {
			t.Fatalf("expected err %v, got err: %v", expectedErr, err)
		}
	})
	t.Run("change root project group parent", func(t *testing.T) {

		var rootPG *types.ProjectGroup
		rootPG, err := cs.ah.GetProjectGroup(ctx, path.Join("user", user.Name))
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		rootPG.Parent.ID = path.Join("user", user.Name, "pg01")

		expectedErr := "cannot change root project group parent type or id"
		_, err = cs.ah.UpdateProjectGroup(ctx, &action.UpdateProjectGroupRequest{ProjectGroupRef: path.Join("user", user.Name), ProjectGroup: rootPG})
		if err.Error() != expectedErr {
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

		expectedErr := "project group name for root project group must be empty"
		_, err = cs.ah.UpdateProjectGroup(ctx, &action.UpdateProjectGroupRequest{ProjectGroupRef: path.Join("user", user.Name), ProjectGroup: rootPG})
		if err.Error() != expectedErr {
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

		_, err = cs.ah.UpdateProjectGroup(ctx, &action.UpdateProjectGroupRequest{ProjectGroupRef: path.Join("user", user.Name), ProjectGroup: rootPG})
		if err != nil {
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
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()
	logger := zaptest.NewLogger(t, zaptest.Level(zap.InfoLevel))

	cs, tetcd := setupConfigstore(ctx, t, logger, dir)
	defer shutdownEtcd(tetcd)

	t.Logf("starting cs")
	go func() {
		_ = cs.Run(ctx)
	}()

	// TODO(sgotti) change the sleep with a real check that all is ready
	time.Sleep(2 * time.Second)

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

	// create a child projectgroup in org root project group
	_, err = cs.ah.CreateProjectGroup(ctx, &types.ProjectGroup{Name: "subprojectgroup01", Parent: types.Parent{Type: types.ConfigTypeProjectGroup, ID: pg01.ID}, Visibility: types.VisibilityPublic})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	t.Run("delete root project group", func(t *testing.T) {
		expectedErr := "cannot delete root project group"
		err := cs.ah.DeleteProjectGroup(ctx, path.Join("org", org.Name))
		if err.Error() != expectedErr {
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
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()
	logger := zaptest.NewLogger(t, zaptest.Level(zap.InfoLevel))

	cs, tetcd := setupConfigstore(ctx, t, logger, dir)
	defer shutdownEtcd(tetcd)

	t.Logf("starting cs")
	go func() {
		_ = cs.Run(ctx)
	}()

	// TODO(sgotti) change the sleep with a real check that all is ready
	time.Sleep(2 * time.Second)

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

	// create a child projectgroup in org root project group
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

	// delete projectgroup
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
	logger := zaptest.NewLogger(t, zaptest.Level(zap.InfoLevel))

	cs, tetcd := setupConfigstore(ctx, t, logger, dir)
	defer shutdownEtcd(tetcd)

	t.Logf("starting cs")
	go func() { _ = cs.Run(ctx) }()

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

func TestRemoteSource(t *testing.T) {
	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	logger := zaptest.NewLogger(t, zaptest.Level(zap.InfoLevel))

	tests := []struct {
		name string
		f    func(ctx context.Context, t *testing.T, cs *Configstore)
	}{
		{
			name: "test create remote source",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				rs := &types.RemoteSource{
					Name:               "rs01",
					APIURL:             "https://api.example.com",
					Type:               types.RemoteSourceTypeGitea,
					AuthType:           types.RemoteSourceAuthTypeOauth2,
					Oauth2ClientID:     "clientid",
					Oauth2ClientSecret: "clientsecret",
				}
				_, err := cs.ah.CreateRemoteSource(ctx, rs)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
			},
		},
		{
			name: "test create duplicate remote source",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				rs := &types.RemoteSource{
					Name:               "rs01",
					APIURL:             "https://api.example.com",
					Type:               types.RemoteSourceTypeGitea,
					AuthType:           types.RemoteSourceAuthTypeOauth2,
					Oauth2ClientID:     "clientid",
					Oauth2ClientSecret: "clientsecret",
				}
				rs, err := cs.ah.CreateRemoteSource(ctx, rs)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				expectedError := util.NewErrBadRequest(fmt.Errorf(`remotesource "rs01" already exists`))
				_, err = cs.ah.CreateRemoteSource(ctx, rs)
				if err.Error() != expectedError.Error() {
					t.Fatalf("expected err: %v, got err: %v", expectedError.Error(), err.Error())
				}
			},
		},
		{
			name: "test rename remote source",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				rs := &types.RemoteSource{
					Name:               "rs01",
					APIURL:             "https://api.example.com",
					Type:               types.RemoteSourceTypeGitea,
					AuthType:           types.RemoteSourceAuthTypeOauth2,
					Oauth2ClientID:     "clientid",
					Oauth2ClientSecret: "clientsecret",
				}
				rs, err := cs.ah.CreateRemoteSource(ctx, rs)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				rs.Name = "rs02"
				req := &action.UpdateRemoteSourceRequest{
					RemoteSourceRef: "rs01",
					RemoteSource:    rs,
				}
				_, err = cs.ah.UpdateRemoteSource(ctx, req)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
			},
		},
		{
			name: "test update remote source keeping same name",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				rs01 := &types.RemoteSource{
					Name:               "rs01",
					APIURL:             "https://api.example.com",
					Type:               types.RemoteSourceTypeGitea,
					AuthType:           types.RemoteSourceAuthTypeOauth2,
					Oauth2ClientID:     "clientid",
					Oauth2ClientSecret: "clientsecret",
				}
				rs01, err := cs.ah.CreateRemoteSource(ctx, rs01)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				rs01.APIURL = "https://api01.example.com"
				req := &action.UpdateRemoteSourceRequest{
					RemoteSourceRef: "rs01",
					RemoteSource:    rs01,
				}
				_, err = cs.ah.UpdateRemoteSource(ctx, req)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
			},
		},
		{
			name: "test rename remote source to an already existing name",
			f: func(ctx context.Context, t *testing.T, cs *Configstore) {
				rs01 := &types.RemoteSource{
					Name:               "rs01",
					APIURL:             "https://api.example.com",
					Type:               types.RemoteSourceTypeGitea,
					AuthType:           types.RemoteSourceAuthTypeOauth2,
					Oauth2ClientID:     "clientid",
					Oauth2ClientSecret: "clientsecret",
				}
				rs01, err := cs.ah.CreateRemoteSource(ctx, rs01)
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				rs02 := &types.RemoteSource{
					Name:               "rs02",
					APIURL:             "https://api.example.com",
					Type:               types.RemoteSourceTypeGitea,
					AuthType:           types.RemoteSourceAuthTypeOauth2,
					Oauth2ClientID:     "clientid",
					Oauth2ClientSecret: "clientsecret",
				}
				if _, err = cs.ah.CreateRemoteSource(ctx, rs02); err != nil {
					t.Fatalf("unexpected err: %v", err)
				}

				expectedError := util.NewErrBadRequest(fmt.Errorf(`remotesource "rs02" already exists`))
				rs01.Name = "rs02"
				req := &action.UpdateRemoteSourceRequest{
					RemoteSourceRef: "rs01",
					RemoteSource:    rs01,
				}
				_, err = cs.ah.UpdateRemoteSource(ctx, req)
				if err.Error() != expectedError.Error() {
					t.Fatalf("expected err: %v, got err: %v", expectedError.Error(), err.Error())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := ioutil.TempDir(dir, "agola")
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			ctx := context.Background()

			cs, tetcd := setupConfigstore(ctx, t, logger, dir)
			defer shutdownEtcd(tetcd)

			t.Logf("starting cs")
			go func() { _ = cs.Run(ctx) }()

			// TODO(sgotti) change the sleep with a real check that all is ready
			time.Sleep(2 * time.Second)

			tt.f(ctx, t, cs)
		})
	}
}
