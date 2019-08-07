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
	"bytes"
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	slog "agola.io/agola/internal/log"
	"github.com/docker/docker/api/types"
	uuid "github.com/satori/go.uuid"
	"agola.io/agola/internal/testutil"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)

func TestDockerPod(t *testing.T) {
	if os.Getenv("SKIP_DOCKER_TESTS") == "1" {
		t.Skip("skipping since env var SKIP_DOCKER_TESTS is 1")
	}
	toolboxPath := os.Getenv("AGOLA_TOOLBOX_PATH")
	if toolboxPath == "" {
		t.Fatalf("env var AGOLA_TOOLBOX_PATH is undefined")
	}

	dir, err := ioutil.TempDir("", "agola")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	defer os.RemoveAll(dir)

	d, err := NewDockerDriver(logger, "executorid01", dir, toolboxPath)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	ctx := context.Background()

	if err := d.Setup(ctx); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	t.Run("create a pod with one container", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.NewV4().String(),
			TaskID: uuid.NewV4().String(),
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
		defer func() { _ = pod.Remove(ctx) }()
	})

	t.Run("execute a command inside a pod", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.NewV4().String(),
			TaskID: uuid.NewV4().String(),
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
		defer func() { _ = pod.Remove(ctx) }()

		ce, err := pod.Exec(ctx, &ExecConfig{
			Cmd: []string{"ls"},
		})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		code, err := ce.Wait(ctx)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if code != 0 {
			t.Fatalf("unexpected exit code: %d", code)
		}
	})

	t.Run("test pod environment", func(t *testing.T) {
		env := map[string]string{
			"ENV01": "ENVVALUE01",
			"ENV02": "ENVVALUE02",
		}

		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.NewV4().String(),
			TaskID: uuid.NewV4().String(),
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
		defer func() { _ = pod.Remove(ctx) }()

		var buf bytes.Buffer
		ce, err := pod.Exec(ctx, &ExecConfig{
			Cmd:    []string{"env"},
			Stdout: &buf,
			Stderr: &buf,
		})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		code, err := ce.Wait(ctx)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if code != 0 {
			t.Fatalf("unexpected exit code: %d", code)
		}

		curEnv, err := testutil.ParseEnvs(bytes.NewReader(buf.Bytes()))
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
	})

	t.Run("create a pod with two containers", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.NewV4().String(),
			TaskID: uuid.NewV4().String(),
			Containers: []*ContainerConfig{
				&ContainerConfig{
					Cmd:   []string{"cat"},
					Image: "busybox",
				},
				&ContainerConfig{
					Image: "nginx:1.16",
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, ioutil.Discard)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		defer func() { _ = pod.Remove(ctx) }()
	})

	t.Run("test communication between two containers", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.NewV4().String(),
			TaskID: uuid.NewV4().String(),
			Containers: []*ContainerConfig{
				&ContainerConfig{
					Cmd:   []string{"cat"},
					Image: "busybox",
				},
				&ContainerConfig{
					Image: "nginx:1.16",
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, ioutil.Discard)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		defer func() { _ = pod.Remove(ctx) }()

		// wait for nginx up
		time.Sleep(1 * time.Second)

		ce, err := pod.Exec(ctx, &ExecConfig{
			Cmd: []string{"nc", "-z", "localhost", "80"},
		})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		code, err := ce.Wait(ctx)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if code != 0 {
			t.Fatalf("unexpected exit code: %d", code)
		}
	})

	t.Run("test get pods single container", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.NewV4().String(),
			TaskID: uuid.NewV4().String(),
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
		defer func() { _ = pod.Remove(ctx) }()

		pods, err := d.GetPods(ctx, true)
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
						t.Fatalf("different container id, want: %q, got: %q", c.ID, ip.containers[i].ID)
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
	})

	t.Run("test get pods two containers", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.NewV4().String(),
			TaskID: uuid.NewV4().String(),
			Containers: []*ContainerConfig{
				&ContainerConfig{
					Cmd:   []string{"cat"},
					Image: "busybox",
				},
				&ContainerConfig{
					Image: "nginx:1.16",
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, ioutil.Discard)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		defer func() { _ = pod.Remove(ctx) }()

		pods, err := d.GetPods(ctx, true)
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
						t.Fatalf("different container id, want: %q, got: %q", c.ID, ip.containers[i].ID)
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
	})

	t.Run("test get pods with two containers and the first already deleted", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.NewV4().String(),
			TaskID: uuid.NewV4().String(),
			Containers: []*ContainerConfig{
				&ContainerConfig{
					Cmd:   []string{"cat"},
					Image: "busybox",
				},
				&ContainerConfig{
					Image: "nginx:1.16",
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, ioutil.Discard)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		defer func() { _ = pod.Remove(ctx) }()

		// delete the first container
		dp := pod.(*DockerPod)
		if err := dp.client.ContainerRemove(ctx, dp.containers[0].ID, types.ContainerRemoveOptions{Force: true}); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		pods, err := d.GetPods(ctx, true)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		ok := false
		for _, p := range pods {
			if p.ID() == pod.ID() {
				ok = true
				ip := pod.(*DockerPod)
				dp := p.(*DockerPod)
				if len(dp.containers) != 1 {
					t.Fatalf("expected 1 container, got %d containers", len(dp.containers))
				}
				if dp.containers[0].ID != ip.containers[1].ID {
					t.Fatalf("different container id, want: %q, got: %q", dp.containers[0].ID, ip.containers[1].ID)
				}
				if diff := cmp.Diff(ip.containers[1], dp.containers[0]); diff != "" {
					t.Error(diff)
				}
			}
		}
		if !ok {
			t.Fatalf("pod with id %q not found", pod.ID())
		}
	})
}
