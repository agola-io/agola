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
	"io"
	"os"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/gofrs/uuid"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"agola.io/agola/internal/testutil"
)

func TestDockerPod(t *testing.T) {
	if os.Getenv("SKIP_DOCKER_TESTS") == "1" {
		t.Skip("skipping since env var SKIP_DOCKER_TESTS is 1")
	}
	toolboxPath := os.Getenv("AGOLA_TOOLBOX_PATH")
	assert.Assert(t, toolboxPath != "", "env var AGOLA_TOOLBOX_PATH is undefined")

	log := testutil.NewLogger(t)

	initImage := "busybox:stable"

	d, err := NewDockerDriver(log, "executorid01", toolboxPath, initImage, nil)
	testutil.NilError(t, err)

	ctx := context.Background()
	err = d.Setup(ctx)
	testutil.NilError(t, err)

	t.Run("create a pod with one container", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.Must(uuid.NewV4()).String(),
			TaskID: uuid.Must(uuid.NewV4()).String(),
			Containers: []*ContainerConfig{
				{
					Cmd:   []string{"cat"},
					Image: "busybox",
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, io.Discard)
		testutil.NilError(t, err)

		defer func() { _ = pod.Remove(ctx) }()
	})

	t.Run("execute a command inside a pod", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.Must(uuid.NewV4()).String(),
			TaskID: uuid.Must(uuid.NewV4()).String(),
			Containers: []*ContainerConfig{
				{
					Cmd:   []string{"cat"},
					Image: "busybox",
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, io.Discard)
		testutil.NilError(t, err)

		defer func() { _ = pod.Remove(ctx) }()

		ce, err := pod.Exec(ctx, &ExecConfig{
			Cmd: []string{"ls"},
		})
		testutil.NilError(t, err)

		code, err := ce.Wait(ctx)
		testutil.NilError(t, err)

		assert.Equal(t, code, 0)
	})

	t.Run("test pod environment", func(t *testing.T) {
		env := map[string]string{
			"ENV01": "ENVVALUE01",
			"ENV02": "ENVVALUE02",
		}

		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.Must(uuid.NewV4()).String(),
			TaskID: uuid.Must(uuid.NewV4()).String(),
			Containers: []*ContainerConfig{
				{
					Cmd:   []string{"cat"},
					Image: "busybox",
					Env:   env,
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, io.Discard)
		testutil.NilError(t, err)

		defer func() { _ = pod.Remove(ctx) }()

		var buf bytes.Buffer
		ce, err := pod.Exec(ctx, &ExecConfig{
			Cmd:    []string{"env"},
			Stdout: &buf,
			Stderr: &buf,
		})
		testutil.NilError(t, err)

		code, err := ce.Wait(ctx)
		testutil.NilError(t, err)

		assert.Equal(t, code, 0)

		curEnv, err := testutil.ParseEnvs(bytes.NewReader(buf.Bytes()))
		testutil.NilError(t, err)

		for n, e := range env {
			ce, ok := curEnv[n]
			assert.Assert(t, ok, "missing env var %s", n)
			assert.Equal(t, ce, e, "different env var %s value, want: %q, got %q", n, e, ce)
		}
	})

	t.Run("create a pod with two containers", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.Must(uuid.NewV4()).String(),
			TaskID: uuid.Must(uuid.NewV4()).String(),
			Containers: []*ContainerConfig{
				{
					Cmd:   []string{"cat"},
					Image: "busybox",
				},
				{
					Image: "nginx:1.16",
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, io.Discard)
		testutil.NilError(t, err)

		defer func() { _ = pod.Remove(ctx) }()
	})

	t.Run("test communication between two containers", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.Must(uuid.NewV4()).String(),
			TaskID: uuid.Must(uuid.NewV4()).String(),
			Containers: []*ContainerConfig{
				{
					Cmd:   []string{"cat"},
					Image: "busybox",
				},
				{
					Image: "nginx:1.16",
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, io.Discard)
		testutil.NilError(t, err)

		defer func() { _ = pod.Remove(ctx) }()

		// wait for nginx up
		time.Sleep(1 * time.Second)

		ce, err := pod.Exec(ctx, &ExecConfig{
			Cmd: []string{"nc", "-z", "localhost", "80"},
		})
		testutil.NilError(t, err)

		code, err := ce.Wait(ctx)
		testutil.NilError(t, err)

		assert.Equal(t, code, 0)
	})

	t.Run("test get pods single container", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.Must(uuid.NewV4()).String(),
			TaskID: uuid.Must(uuid.NewV4()).String(),
			Containers: []*ContainerConfig{
				{
					Cmd:   []string{"cat"},
					Image: "busybox",
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, io.Discard)
		testutil.NilError(t, err)

		defer func() { _ = pod.Remove(ctx) }()

		pods, err := d.GetPods(ctx, true)
		testutil.NilError(t, err)

		ok := false
		for _, p := range pods {
			if p.ID() == pod.ID() {
				ok = true
				ip := pod.(*DockerPod)
				dp := p.(*DockerPod)
				for i, c := range dp.containers {
					assert.Equal(t, c.ID, ip.containers[i].ID)
					assert.DeepEqual(t, ip.containers[i], c)
				}
			}
		}
		if !ok {
			t.Fatalf("pod with id %q not found", pod.ID())
		}
	})

	t.Run("test get pods two containers", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.Must(uuid.NewV4()).String(),
			TaskID: uuid.Must(uuid.NewV4()).String(),
			Containers: []*ContainerConfig{
				{
					Cmd:   []string{"cat"},
					Image: "busybox",
				},
				{
					Image: "nginx:1.16",
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, io.Discard)
		testutil.NilError(t, err)

		defer func() { _ = pod.Remove(ctx) }()

		pods, err := d.GetPods(ctx, true)
		testutil.NilError(t, err)

		ok := false
		for _, p := range pods {
			if p.ID() == pod.ID() {
				ok = true
				ip := pod.(*DockerPod)
				dp := p.(*DockerPod)
				for i, c := range dp.containers {
					assert.Equal(t, c.ID, ip.containers[i].ID)
					assert.DeepEqual(t, ip.containers[i], c)
				}
			}
		}
		if !ok {
			t.Fatalf("pod with id %q not found", pod.ID())
		}
	})

	t.Run("test get pods with two containers and the first already deleted", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.Must(uuid.NewV4()).String(),
			TaskID: uuid.Must(uuid.NewV4()).String(),
			Containers: []*ContainerConfig{
				{
					Cmd:   []string{"cat"},
					Image: "busybox",
				},
				{
					Image: "nginx:1.16",
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, io.Discard)
		testutil.NilError(t, err)

		defer func() { _ = pod.Remove(ctx) }()

		// delete the first container
		dp := pod.(*DockerPod)
		err = dp.client.ContainerRemove(ctx, dp.containers[0].ID, types.ContainerRemoveOptions{Force: true})
		testutil.NilError(t, err)

		pods, err := d.GetPods(ctx, true)
		testutil.NilError(t, err)

		ok := false
		for _, p := range pods {
			if p.ID() == pod.ID() {
				ok = true
				ip := pod.(*DockerPod)
				dp := p.(*DockerPod)
				assert.Assert(t, cmp.Len(dp.containers, 1))
				assert.Equal(t, dp.containers[0].ID, ip.containers[1].ID)
				assert.DeepEqual(t, ip.containers[1], dp.containers[0])
			}
		}
		if !ok {
			t.Fatalf("pod with id %q not found", pod.ID())
		}
	})

	t.Run("test pod with a tmpfs volume with size limit", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.Must(uuid.NewV4()).String(),
			TaskID: uuid.Must(uuid.NewV4()).String(),
			Containers: []*ContainerConfig{
				{
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
		}, io.Discard)
		testutil.NilError(t, err)

		defer func() { _ = pod.Remove(ctx) }()

		ce, err := pod.Exec(ctx, &ExecConfig{
			Cmd: []string{"sh", "-c", "if [ $(grep /mnt/tmpfs /proc/mounts | grep -c size=1024k) -ne 1 ]; then exit 1; fi"},
		})
		testutil.NilError(t, err)

		code, err := ce.Wait(ctx)
		testutil.NilError(t, err)

		assert.Equal(t, code, 0)
	})

	t.Run("test pod with a tmpfs volume without size limit", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.Must(uuid.NewV4()).String(),
			TaskID: uuid.Must(uuid.NewV4()).String(),
			Containers: []*ContainerConfig{
				{
					Cmd:   []string{"cat"},
					Image: "busybox",
					Volumes: []Volume{
						{
							Path:  "/mnt/tmpfs",
							TmpFS: &VolumeTmpFS{},
						},
					},
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, io.Discard)
		testutil.NilError(t, err)

		defer func() { _ = pod.Remove(ctx) }()

		ce, err := pod.Exec(ctx, &ExecConfig{
			Cmd: []string{"sh", "-c", "if [ $(grep -c /mnt/tmpfs /proc/mounts) -ne 1 ]; then exit 1; fi"},
		})
		testutil.NilError(t, err)

		code, err := ce.Wait(ctx)
		testutil.NilError(t, err)

		assert.Equal(t, code, 0)
	})

	t.Run("test pod with two tmpfs volumes with size limit", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.Must(uuid.NewV4()).String(),
			TaskID: uuid.Must(uuid.NewV4()).String(),
			Containers: []*ContainerConfig{
				{
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
		}, io.Discard)
		testutil.NilError(t, err)

		defer func() { _ = pod.Remove(ctx) }()

		ce, err := pod.Exec(ctx, &ExecConfig{
			Cmd: []string{"sh", "-c", "if [ $(grep /mnt/vol1 /proc/mounts | grep -c size=1024k) -ne 1 -o $(grep /mnt/vol2 /proc/mounts | grep -c size=1024k) -ne 1 ]; then exit 1; fi"},
		})
		testutil.NilError(t, err)

		code, err := ce.Wait(ctx)
		testutil.NilError(t, err)

		assert.Equal(t, code, 0)
	})

	t.Run("test pod with two tmpfs volumes one with size limit and one without", func(t *testing.T) {
		pod, err := d.NewPod(ctx, &PodConfig{
			ID:     uuid.Must(uuid.NewV4()).String(),
			TaskID: uuid.Must(uuid.NewV4()).String(),
			Containers: []*ContainerConfig{
				{
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
							Path:  "/mnt/vol2",
							TmpFS: &VolumeTmpFS{},
						},
					},
				},
			},
			InitVolumeDir: "/tmp/agola",
		}, io.Discard)
		testutil.NilError(t, err)

		defer func() { _ = pod.Remove(ctx) }()

		ce, err := pod.Exec(ctx, &ExecConfig{
			Cmd: []string{"sh", "-c", "if [ $(grep /mnt/vol1 /proc/mounts | grep -c size=1024k) -ne 1 -o $(grep -c /mnt/vol2 /proc/mounts) -ne 1 ]; then exit 1; fi"},
		})
		testutil.NilError(t, err)

		code, err := ce.Wait(ctx)
		testutil.NilError(t, err)

		assert.Equal(t, code, 0)
	})
}
