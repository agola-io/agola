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
	"reflect"
	"testing"
	"time"

	"agola.io/agola/internal/testutil"

	uuid "github.com/satori/go.uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestK8sPod(t *testing.T) {
	if os.Getenv("SKIP_K8S_TESTS") == "1" {
		t.Skip("skipping since env var SKIP_K8S_TESTS is 1")
	}
	toolboxPath := os.Getenv("AGOLA_TOOLBOX_PATH")
	if toolboxPath == "" {
		t.Fatalf("env var AGOLA_TOOLBOX_PATH is undefined")
	}

	logger := zaptest.NewLogger(t, zaptest.Level(zap.InfoLevel))

	d, err := NewK8sDriver(logger, "executorid01", toolboxPath)
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

		var buf bytes.Buffer
		ce, err := pod.Exec(ctx, &ExecConfig{
			Cmd:    []string{"ls"},
			Stdout: &buf,
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
			Stderr: os.Stdout,
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

		var buf bytes.Buffer
		ce, err := pod.Exec(ctx, &ExecConfig{
			Cmd:    []string{"nc", "-z", "localhost", "80"},
			Stdout: &buf,
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

	t.Run("test get pods", func(t *testing.T) {
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
			}
		}
		if !ok {
			t.Fatalf("pod with id %q not found", pod.ID())
		}
	})

	t.Run("test pod with a tmpfs volume", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.NewV4().String(),
			TaskID: uuid.NewV4().String(),
			Containers: []*ContainerConfig{
				&ContainerConfig{
					Cmd:   []string{"cat"},
					Image: "busybox",
					Volumes: []Volume{
						{
							Path: "/mnt/tmpfs",
							TmpFS: &VolumeTmpFS{
								Size: 1024 * 1024,
							},
						},
					},
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
			// k8s doesn't set size=1024k in the tmpf mount options but uses other modes to detect the size
			Cmd:    []string{"sh", "-c", "if [ $(grep -c /mnt/tmpfs /proc/mounts) -ne 1 ]; then exit 1; fi"},
			Stdout: &buf,
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

	t.Run("test pod with two tmpfs volumes", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.NewV4().String(),
			TaskID: uuid.NewV4().String(),
			Containers: []*ContainerConfig{
				&ContainerConfig{
					Cmd:   []string{"cat"},
					Image: "busybox",
					Volumes: []Volume{
						{
							Path: "/mnt/vol1",
							TmpFS: &VolumeTmpFS{
								Size: 1024 * 1024,
							},
						},
						{
							Path: "/mnt/vol2",
							TmpFS: &VolumeTmpFS{
								Size: 1024 * 1024,
							},
						},
					},
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
			// k8s doesn't set size=1024k in the tmpf mount options but uses other modes to detect the size
			Cmd:    []string{"sh", "-c", "if [ $(grep -c /mnt/vol1 /proc/mounts) -ne 1 -o $(grep -c /mnt/vol2 /proc/mounts) ]; then exit 1; fi"},
			Stdout: &buf,
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
}

func TestParseGitVersion(t *testing.T) {
	tests := []struct {
		gitVersion string
		out        *serverVersion
		err        bool
	}{
		{
			gitVersion: "v1.8.0",
			out:        &serverVersion{Major: 1, Minor: 8},
		},
		{
			gitVersion: "v1.12.0",
			out:        &serverVersion{Major: 1, Minor: 12},
		},
		{
			gitVersion: "v1.12.20",
			out:        &serverVersion{Major: 1, Minor: 12},
		},
		{
			gitVersion: "v1.12.8-test.10",
			out:        &serverVersion{Major: 1, Minor: 12},
		},
		{
			gitVersion: "v1.a",
			err:        true,
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			sv, err := parseGitVersion(tt.gitVersion)
			if tt.err {
				if err == nil {
					t.Errorf("expected error, got nil error")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected err: %v", err)
				return
			}
			if !reflect.DeepEqual(sv, tt.out) {
				t.Errorf("expected %v, got %v", tt.out, sv)
			}
		})
	}
}
