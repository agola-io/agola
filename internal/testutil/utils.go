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

package testutil

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"agola.io/agola/internal/etcd"
	"go.etcd.io/etcd/embed"
	"go.uber.org/zap"

	uuid "github.com/satori/go.uuid"
	"github.com/sgotti/gexpect"
)

const (
	sleepInterval = 500 * time.Millisecond
	etcdTimeout   = 5 * time.Second

	MinPort = 2048
	MaxPort = 16384
)

var curPort = MinPort
var portMutex = sync.Mutex{}

type Process struct {
	t    *testing.T
	uid  string
	name string
	args []string
	Cmd  *gexpect.ExpectSubprocess
	bin  string
}

func (p *Process) start() error {
	if p.Cmd != nil {
		panic(fmt.Errorf("%s: cmd not cleanly stopped", p.uid))
	}
	cmd := exec.Command(p.bin, p.args...)
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	p.Cmd = &gexpect.ExpectSubprocess{Cmd: cmd, Output: pw}
	if err := p.Cmd.Start(); err != nil {
		return err
	}
	go func() {
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			p.t.Logf("[%s %s]: %s", p.name, p.uid, scanner.Text())
		}
	}()

	return nil
}

func (p *Process) Start() error {
	if err := p.start(); err != nil {
		return err
	}
	p.Cmd.Continue()
	return nil
}

func (p *Process) StartExpect() error {
	return p.start()
}

func (p *Process) Signal(sig os.Signal) error {
	p.t.Logf("signalling %s %s with %s", p.name, p.uid, sig)
	if p.Cmd == nil {
		panic(fmt.Errorf("p: %s, cmd is empty", p.uid))
	}
	return p.Cmd.Cmd.Process.Signal(sig)
}

func (p *Process) Kill() {
	p.t.Logf("killing %s %s", p.name, p.uid)
	if p.Cmd == nil {
		panic(fmt.Errorf("p: %s, cmd is empty", p.uid))
	}
	p.Cmd.Cmd.Process.Signal(os.Kill)
	p.Cmd.Wait()
	p.Cmd = nil
}

func (p *Process) Stop() {
	p.t.Logf("stopping %s %s", p.name, p.uid)
	if p.Cmd == nil {
		panic(fmt.Errorf("p: %s, cmd is empty", p.uid))
	}
	p.Cmd.Continue()
	p.Cmd.Cmd.Process.Signal(os.Interrupt)
	p.Cmd.Wait()
	p.Cmd = nil
}

func (p *Process) Wait(timeout time.Duration) error {
	timeoutCh := time.NewTimer(timeout).C
	endCh := make(chan error)
	go func() {
		err := p.Cmd.Wait()
		endCh <- err
	}()
	select {
	case <-timeoutCh:
		return fmt.Errorf("timeout waiting on process")
	case <-endCh:
		return nil
	}
}

type TestEmbeddedEtcd struct {
	t *testing.T
	*TestEtcd
	Etcd          *embed.Etcd
	Endpoint      string
	ListenAddress string
	Port          string
}

func NewTestEmbeddedEtcd(t *testing.T, logger *zap.Logger, dir string, a ...string) (*TestEmbeddedEtcd, error) {
	u := uuid.NewV4()
	uid := fmt.Sprintf("%x", u[:4])

	dataDir := filepath.Join(dir, fmt.Sprintf("etcd%s", uid))

	listenAddress, port, err := GetFreePort(true, false)
	if err != nil {
		return nil, err
	}
	listenAddress2, port2, err := GetFreePort(true, false)
	if err != nil {
		return nil, err
	}

	cfg := embed.NewConfig()
	cfg.Name = uid
	cfg.Dir = dataDir
	cfg.Logger = "zap"
	cfg.LogOutputs = []string{"stdout"}
	lcurl, _ := url.Parse(fmt.Sprintf("http://%s:%s", listenAddress, port))
	lpurl, _ := url.Parse(fmt.Sprintf("http://%s:%s", listenAddress2, port2))

	cfg.LCUrls = []url.URL{*lcurl}
	cfg.ACUrls = []url.URL{*lcurl}
	cfg.LPUrls = []url.URL{*lpurl}
	cfg.APUrls = []url.URL{*lpurl}

	cfg.InitialCluster = cfg.InitialClusterFromName(cfg.Name)

	t.Logf("starting embedded etcd server")
	embeddedEtcd, err := embed.StartEtcd(cfg)
	if err != nil {
		return nil, err
	}

	storeEndpoint := fmt.Sprintf("http://%s:%s", listenAddress, port)

	storeConfig := etcd.Config{
		Logger:    logger,
		Endpoints: storeEndpoint,
	}
	e, err := etcd.New(storeConfig)
	if err != nil {
		return nil, fmt.Errorf("cannot create store: %v", err)
	}

	tectd := &TestEmbeddedEtcd{
		t: t,
		TestEtcd: &TestEtcd{
			e,
			t,
		},
		Etcd:          embeddedEtcd,
		Endpoint:      storeEndpoint,
		ListenAddress: listenAddress,
		Port:          port,
	}
	return tectd, nil
}

func (te *TestEmbeddedEtcd) Start() error {
	<-te.Etcd.Server.ReadyNotify()
	return nil
}

func (te *TestEmbeddedEtcd) Stop() error {
	te.Etcd.Close()
	return nil
}

func (te *TestEmbeddedEtcd) Kill() error {
	te.Etcd.Close()
	return nil
}

type TestExternalEtcd struct {
	t *testing.T
	*TestEtcd
	Process
	Endpoint      string
	ListenAddress string
	Port          string
}

func NewTestExternalEtcd(t *testing.T, logger *zap.Logger, dir string, a ...string) (*TestExternalEtcd, error) {
	u := uuid.NewV4()
	uid := fmt.Sprintf("%x", u[:4])

	dataDir := filepath.Join(dir, fmt.Sprintf("etcd%s", uid))

	listenAddress, port, err := GetFreePort(true, false)
	if err != nil {
		return nil, err
	}
	listenAddress2, port2, err := GetFreePort(true, false)
	if err != nil {
		return nil, err
	}

	args := []string{}
	args = append(args, fmt.Sprintf("--name=%s", uid))
	args = append(args, fmt.Sprintf("--data-dir=%s", dataDir))
	args = append(args, fmt.Sprintf("--listen-client-urls=http://%s:%s", listenAddress, port))
	args = append(args, fmt.Sprintf("--advertise-client-urls=http://%s:%s", listenAddress, port))
	args = append(args, fmt.Sprintf("--listen-peer-urls=http://%s:%s", listenAddress2, port2))
	args = append(args, fmt.Sprintf("--initial-advertise-peer-urls=http://%s:%s", listenAddress2, port2))
	args = append(args, fmt.Sprintf("--initial-cluster=%s=http://%s:%s", uid, listenAddress2, port2))
	args = append(args, a...)

	storeEndpoint := fmt.Sprintf("http://%s:%s", listenAddress, port)

	storeConfig := etcd.Config{
		Logger:    logger,
		Endpoints: storeEndpoint,
	}
	e, err := etcd.New(storeConfig)
	if err != nil {
		return nil, fmt.Errorf("cannot create store: %v", err)
	}

	bin := os.Getenv("ETCD_BIN")
	if bin == "" {
		return nil, fmt.Errorf("missing ETCD_BIN env")
	}
	tectd := &TestExternalEtcd{
		t: t,
		TestEtcd: &TestEtcd{
			e,
			t,
		},
		Process: Process{
			t:    t,
			uid:  uid,
			name: "etcd",
			bin:  bin,
			args: args,
		},
		Endpoint:      storeEndpoint,
		ListenAddress: listenAddress,
		Port:          port,
	}
	return tectd, nil
}

type TestEtcd struct {
	*etcd.Store
	t *testing.T
}

func (te *TestEtcd) Compact() error {
	ctx, cancel := context.WithTimeout(context.Background(), etcdTimeout)
	defer cancel()
	resp, err := te.Get(ctx, "anykey", 0)
	if err != nil && err != etcd.ErrKeyNotFound {
		return err
	}

	_, err = te.Client().Compact(ctx, resp.Header.Revision)
	return err
}

func (te *TestEtcd) WaitUp(timeout time.Duration) error {
	start := time.Now()
	for time.Now().Add(-timeout).Before(start) {
		ctx, cancel := context.WithTimeout(context.Background(), etcdTimeout)
		defer cancel()
		_, err := te.Get(ctx, "anykey", 0)
		if err != nil && err == etcd.ErrKeyNotFound {
			return nil
		}
		if err == nil {
			return nil
		}
		time.Sleep(sleepInterval)
	}

	return fmt.Errorf("timeout")
}

func (te *TestEtcd) WaitDown(timeout time.Duration) error {
	start := time.Now()
	for time.Now().Add(-timeout).Before(start) {
		ctx, cancel := context.WithTimeout(context.Background(), etcdTimeout)
		defer cancel()
		_, err := te.Get(ctx, "anykey", 0)
		if err != nil && err != etcd.ErrKeyNotFound {
			return nil
		}
		time.Sleep(sleepInterval)
	}

	return fmt.Errorf("timeout")
}

func testFreeTCPPort(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return err
	}
	ln.Close()
	return nil
}

func testFreeUDPPort(port int) error {
	ln, err := net.ListenPacket("udp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return err
	}
	ln.Close()
	return nil
}

// Hack to find a free tcp and udp port
func GetFreePort(tcp bool, udp bool) (string, string, error) {
	portMutex.Lock()
	defer portMutex.Unlock()

	if !tcp && !udp {
		return "", "", fmt.Errorf("at least one of tcp or udp port shuld be required")
	}
	localhostIP, err := net.ResolveIPAddr("ip", "localhost")
	if err != nil {
		return "", "", fmt.Errorf("failed to resolve ip addr: %v", err)
	}
	for {
		curPort++
		if curPort > MaxPort {
			return "", "", fmt.Errorf("all available ports to test have been exausted")
		}
		if tcp {
			if err := testFreeTCPPort(curPort); err != nil {
				continue
			}
		}
		if udp {
			if err := testFreeUDPPort(curPort); err != nil {
				continue
			}
		}
		return localhostIP.IP.String(), strconv.Itoa(curPort), nil
	}
}
