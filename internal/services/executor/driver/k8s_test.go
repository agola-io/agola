// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package driver

import (
	"bytes"
	"context"
	"io/ioutil"
	"os"
	"testing"

	uuid "github.com/satori/go.uuid"
)

func TestK8sPod(t *testing.T) {
	if os.Getenv("SKIP_K8S_TESTS") == "1" {
		t.Skip("skipping since env var SKIP_K8S_TESTS is 1")
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

	d, err := NewK8sDriver(logger, "executorid01", toolboxPath)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	ctx := context.Background()

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
		defer pod.Remove(ctx)
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
		defer pod.Remove(ctx)

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
		defer pod.Remove(ctx)

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
		defer pod.Remove(ctx)

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

}
