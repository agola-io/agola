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
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/gofrs/uuid"
	"github.com/sgotti/gexpect"
	"github.com/sorintlab/errors"
)

const (
	sleepInterval = 500 * time.Millisecond

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
	env  []string
	Cmd  *gexpect.ExpectSubprocess
	bin  string
}

func (p *Process) start() error {
	if p.Cmd != nil {
		panic(errors.Errorf("%s: cmd not cleanly stopped", p.uid))
	}
	cmd := exec.Command(p.bin, p.args...)
	cmd.Env = p.env

	pr, pw, err := os.Pipe()
	if err != nil {
		return errors.WithStack(err)
	}
	p.Cmd = &gexpect.ExpectSubprocess{Cmd: cmd, Output: pw}
	if err := p.Cmd.Start(); err != nil {
		return errors.WithStack(err)
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
		return errors.WithStack(err)
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
		panic(errors.Errorf("p: %s, cmd is empty", p.uid))
	}
	return errors.WithStack(p.Cmd.Cmd.Process.Signal(sig))
}

func (p *Process) Kill() {
	p.t.Logf("killing %s %s", p.name, p.uid)
	if p.Cmd == nil {
		panic(errors.Errorf("p: %s, cmd is empty", p.uid))
	}
	_ = p.Cmd.Cmd.Process.Signal(os.Kill)
	_ = p.Cmd.Wait()
	p.Cmd = nil
}

func (p *Process) Stop() {
	p.t.Logf("stopping %s %s", p.name, p.uid)
	if p.Cmd == nil {
		panic(errors.Errorf("p: %s, cmd is empty", p.uid))
	}
	p.Cmd.Continue()
	_ = p.Cmd.Cmd.Process.Signal(os.Interrupt)
	_ = p.Cmd.Wait()
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
		return errors.Errorf("timeout waiting on process")
	case <-endCh:
		return nil
	}
}

const (
	giteaAppIniTmpl = `
APP_NAME = Gitea: Git with a cup of tea
RUN_MODE = prod
RUN_USER = {{ .User }}

[repository]
ROOT = {{ .Data }}/git/repositories

[repository.local]
LOCAL_COPY_PATH = {{ .Data }}/gitea/tmp/local-repo

[repository.upload]
TEMP_PATH = {{ .Data }}/gitea/uploads

[server]
APP_DATA_PATH    = {{ .Data }}/gitea
HTTP_ADDR        = {{ .HTTPListenAddress }}
HTTP_PORT        = {{ .HTTPPort }}
ROOT_URL         = http://{{ .HTTPListenAddress }}:{{ .HTTPPort }}/
DISABLE_SSH      = false
# Use built-in ssh server
START_SSH_SERVER = true
SSH_DOMAIN       = {{ .SSHListenAddress }}
SSH_LISTEN_HOST  = {{ .SSHListenAddress }}
SSH_PORT         = {{ .SSHPort }}
LFS_CONTENT_PATH = {{ .Data }}/git/lfs
DOMAIN           = localhost
LFS_START_SERVER = true
LFS_JWT_SECRET   = PI0Tfn0OcYpzpNb_u11JdoUfDbsMa2x6paWH2ckMVrw
OFFLINE_MODE     = false

[database]
PATH     = {{ .Data }}/gitea/gitea.db
DB_TYPE  = sqlite3

[indexer]
ISSUE_INDEXER_PATH = {{ .Data }}/gitea/indexers/issues.bleve

[session]
PROVIDER_CONFIG = {{ .Data }}/gitea/sessions
PROVIDER        = file

[picture]
AVATAR_UPLOAD_PATH      = {{ .Data }}/gitea/avatars
DISABLE_GRAVATAR        = false
ENABLE_FEDERATED_AVATAR = true

[attachment]
PATH = {{ .Data }}/gitea/attachments

[log]
ROOT_PATH = {{ .Data }}/gitea/log
MODE      = file
LEVEL     = info

[security]
INSTALL_LOCK   = true
SECRET_KEY     = vRCH8usxWj6e8JGBPBaqycpfVyWm079xC3P3k76YsjKbrgBmyHhQD9UyzRFICKBT
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE1NTc0MDI0MDZ9.27f4bakIxBIOoO48ORyLmbvpQprsJMEHLM6PyXIqB5g

[service]
DISABLE_REGISTRATION              = false
REQUIRE_SIGNIN_VIEW               = false
REGISTER_EMAIL_CONFIRM            = false
ENABLE_NOTIFY_MAIL                = false
ALLOW_ONLY_EXTERNAL_REGISTRATION  = false
ENABLE_CAPTCHA                    = false
DEFAULT_KEEP_EMAIL_PRIVATE        = false
DEFAULT_ALLOW_CREATE_ORGANIZATION = true
DEFAULT_ENABLE_TIMETRACKING       = true
NO_REPLY_ADDRESS                  = noreply.example.org

[oauth2]
JWT_SECRET = hQdtj6H6lsd8vG6V1vCPYcOn8uP2C3i_bbnDozfCcIY

[mailer]
ENABLED = false

[openid]
ENABLE_OPENID_SIGNIN = true
ENABLE_OPENID_SIGNUP = true
    `
)

type GiteaConfig struct {
	Data              string
	User              string
	HTTPListenAddress string
	HTTPPort          string
	SSHListenAddress  string
	SSHPort           string
}

type TestGitea struct {
	Process

	GiteaPath         string
	ConfigPath        string
	HTTPListenAddress string
	HTTPPort          string
	SSHListenAddress  string
	SSHPort           string
}

func NewTestGitea(t *testing.T, dir, dockerBridgeAddress string, a ...string) (*TestGitea, error) {
	u := uuid.Must(uuid.NewV4())
	uid := fmt.Sprintf("%x", u[:4])

	giteaPath := os.Getenv("GITEA_PATH")
	if giteaPath == "" {
		t.Fatalf("env var GITEA_PATH is undefined")
	}

	giteaDir := filepath.Join(dir, "gitea")

	if err := os.MkdirAll(giteaDir, 0775); err != nil {
		return nil, errors.WithStack(err)
	}

	// override default gitconfig file to make it unique for gitea instance.
	// We have to override the HOME env var since GIT_CONFIG env is ignored.
	//
	// keep current env
	env := os.Environ()
	env = append(env, "HOME="+giteaDir)

	// setup $HOME/.gitconfig
	gitConfigData := `
[user]
    name = TestGitea
    email = testgitea@example.com
`
	if err := os.WriteFile(filepath.Join(giteaDir, ".gitconfig"), []byte(gitConfigData), 0644); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	curUser, err := user.Current()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	httpPort, err := GetFreePort(dockerBridgeAddress, true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	sshPort, err := GetFreePort(dockerBridgeAddress, true, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	giteaConfig := &GiteaConfig{
		Data:              giteaDir,
		User:              curUser.Username,
		HTTPListenAddress: dockerBridgeAddress,
		SSHListenAddress:  dockerBridgeAddress,
		HTTPPort:          httpPort,
		SSHPort:           sshPort,
	}
	tmpl, err := template.New("gitea").Parse(giteaAppIniTmpl)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	conf := &bytes.Buffer{}
	if err := tmpl.Execute(conf, giteaConfig); err != nil {
		return nil, errors.WithStack(err)
	}

	if err := os.MkdirAll(filepath.Join(giteaDir, "conf"), 0775); err != nil {
		return nil, errors.WithStack(err)
	}
	if err := os.MkdirAll(filepath.Join(giteaDir, "log"), 0775); err != nil {
		return nil, errors.WithStack(err)
	}
	configPath := filepath.Join(giteaDir, "conf", "app.ini")
	if err := os.WriteFile(configPath, conf.Bytes(), 0664); err != nil {
		return nil, errors.WithStack(err)
	}

	args := []string{}
	args = append(args, "web", "--config", configPath)

	tgitea := &TestGitea{
		Process: Process{
			t:    t,
			uid:  uid,
			name: "gitea",
			bin:  giteaPath,
			args: args,
			env:  env,
		},
		GiteaPath:         giteaPath,
		ConfigPath:        configPath,
		HTTPListenAddress: dockerBridgeAddress,
		HTTPPort:          httpPort,
		SSHListenAddress:  dockerBridgeAddress,
		SSHPort:           sshPort,
	}

	return tgitea, nil
}

type CheckFunc func() (bool, error)

func Wait(timeout time.Duration, f CheckFunc) error {
	start := time.Now()
	for time.Now().Add(-timeout).Before(start) {
		ok, err := f()
		if err != nil {
			return errors.WithStack(err)
		}
		if ok {
			return nil
		}
		time.Sleep(sleepInterval)
	}
	return errors.Errorf("timeout")
}

func testFreeTCPPort(host string, port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return errors.WithStack(err)
	}
	ln.Close()
	return nil
}

func testFreeUDPPort(host string, port int) error {
	ln, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return errors.WithStack(err)
	}
	ln.Close()
	return nil
}

// Hack to find a free tcp and udp port
func GetFreePort(host string, tcp bool, udp bool) (string, error) {
	portMutex.Lock()
	defer portMutex.Unlock()

	if !tcp && !udp {
		return "", errors.Errorf("at least one of tcp or udp port shuld be required")
	}
	for {
		curPort++
		if curPort > MaxPort {
			return "", errors.Errorf("all available ports to test have been exausted")
		}
		if tcp {
			if err := testFreeTCPPort(host, curPort); err != nil {
				continue
			}
		}
		if udp {
			if err := testFreeUDPPort(host, curPort); err != nil {
				continue
			}
		}
		return strconv.Itoa(curPort), nil
	}
}
