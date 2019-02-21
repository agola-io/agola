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
	"reflect"
	"testing"
	"time"

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
		if _, err := cs1.ch.CreateProject(ctx, &types.Project{Name: fmt.Sprintf("project%d", i)}); err != nil {
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
		if _, err := cs1.ch.CreateProject(ctx, &types.Project{Name: fmt.Sprintf("project%d", i)}); err != nil {
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

	projects1, err := cs1.readDB.GetProjects("", 0, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	projects2, err := cs2.readDB.GetProjects("", 0, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !compareProjects(projects1, projects2) {
		t.Logf("len(projects1): %d", len(projects1))
		t.Logf("len(projects2): %d", len(projects2))
		t.Logf("projects1: %s", util.Dump(projects1))
		t.Logf("projects2: %s", util.Dump(projects2))
		t.Fatalf("projects are different between the two readdbs")
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

	projects1, err = cs1.readDB.GetProjects("", 0, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	projects3, err := cs3.readDB.GetProjects("", 0, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !compareProjects(projects1, projects3) {
		t.Logf("len(projects1): %d", len(projects1))
		t.Logf("len(projects3): %d", len(projects3))
		t.Logf("projects1: %s", util.Dump(projects1))
		t.Logf("projects3: %s", util.Dump(projects3))
		t.Fatalf("projects are different between the two readdbs")
	}
}

func compareProjects(p1, p2 []*types.Project) bool {
	p1ids := map[string]struct{}{}
	p2ids := map[string]struct{}{}

	for _, p := range p1 {
		p1ids[p.ID] = struct{}{}
	}
	for _, p := range p2 {
		p2ids[p.ID] = struct{}{}
	}

	return reflect.DeepEqual(p1ids, p2ids)
}
