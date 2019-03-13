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

package driver

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"unicode"

	slog "github.com/sorintlab/agola/internal/log"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)
var log = logger.Sugar()

func parseEnv(envvar string) (string, string, error) {
	// trim white spaces at the start
	envvar = strings.TrimLeftFunc(envvar, unicode.IsSpace)
	arr := strings.SplitN(envvar, "=", 2)
	varname := arr[0]
	if varname == "" {
		return "", "", fmt.Errorf("invalid environment variable definition: %s", envvar)
	}
	if len(arr) > 1 {
		if arr[1] == "" {
			return "", "", fmt.Errorf("invalid environment variable definition: %s", envvar)
		}
		return varname, arr[1], nil
	}
	return varname, "", nil
}

func parseEnvs(r io.Reader) (map[string]string, error) {
	envs := map[string]string{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		envname, envvalue, err := parseEnv(scanner.Text())
		if err != nil {
			return nil, err
		}
		envs[envname] = envvalue
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return envs, nil
}

func TestPod(t *testing.T) {
	if os.Getenv("SKIP_DOCKER_TESTS") == "1" {
		t.Skip("skipping since env var SKIP_DOCKER_TESTS is 1")
	}

	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	d, err := NewDockerDriver(logger, dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	ctx := context.Background()

	t.Run("create a pod with one container", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			Containers: []*ContainerConfig{
				&ContainerConfig{
					Cmd:   []string{"cat"},
					Image: "busybox",
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, ioutil.Discard)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		defer pod.Remove(ctx)
	})

	t.Run("execute a command inside a pod", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			Containers: []*ContainerConfig{
				&ContainerConfig{
					Cmd:   []string{"cat"},
					Image: "busybox",
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, ioutil.Discard)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		ce, err := pod.Exec(ctx, &ExecConfig{
			Cmd: []string{"ls"},
		})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		ce.Stdin().Close()
		code, err := ce.Wait(ctx)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if code != 0 {
			t.Fatalf("unexpected exito code: %d", code)
		}

		defer pod.Remove(ctx)
	})

	t.Run("test pod environment", func(t *testing.T) {
		env := map[string]string{
			"ENV01": "ENVVALUE01",
			"ENV02": "ENVVALUE02",
		}

		pod, err := d.NewPod(ctx, &PodConfig{
			Containers: []*ContainerConfig{
				&ContainerConfig{
					Cmd:   []string{"cat"},
					Image: "busybox",
					Env:   env,
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, ioutil.Discard)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		var buf bytes.Buffer
		ce, err := pod.Exec(ctx, &ExecConfig{
			Cmd:    []string{"env"},
			Stdout: &buf,
			Stderr: &buf,
		})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		ce.Stdin().Close()
		code, err := ce.Wait(ctx)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if code != 0 {
			t.Fatalf("unexpected exit code: %d", code)
		}

		curEnv, err := parseEnvs(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		for n, e := range env {
			if ce, ok := curEnv[n]; !ok {
				t.Fatalf("missing env var %s", n)
			} else {
				if ce != e {
					t.Fatalf("different env var %s value, want: %q, got %q", n, e, ce)
				}
			}
		}

		defer pod.Remove(ctx)
	})

	t.Run("test get pods by label", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			Containers: []*ContainerConfig{
				&ContainerConfig{
					Cmd:   []string{"cat"},
					Image: "busybox",
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, ioutil.Discard)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		pods, err := d.GetPodsByLabels(ctx, map[string]string{}, true)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		ok := false
		for _, p := range pods {
			if p.ID() == pod.ID() {
				ok = true
				ip := pod.(*DockerPod)
				dp := p.(*DockerPod)
				for i, c := range dp.containers {
					if c.ID != ip.containers[i].ID {
						t.Fatalf("different pod id, want: %s, got: %s", ip.id, dp.id)
					}
					if diff := cmp.Diff(ip.containers[i], c); diff != "" {
						t.Error(diff)
					}
				}
			}
		}
		if !ok {
			t.Fatalf("pod with id %q not found", pod.ID())
		}

		defer pod.Remove(ctx)
	})

}
