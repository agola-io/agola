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
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"agola.io/agola/internal/services/executor/registry"
	"agola.io/agola/services/types"
)

const (
	toolboxPrefix = "agola-toolbox"

	labelPrefix = "agola.io/"

	agolaLabelKey   = labelPrefix + "agola"
	agolaLabelValue = "true"

	executorIDKey = labelPrefix + "executorid"
	podIDKey      = labelPrefix + "podid"
	taskIDKey     = labelPrefix + "taskid"

	containerIndexKey = labelPrefix + "containerindex"
)

// Driver is a generic interface around the pod concept (a group of "containers"
// sharing, at least, the same network namespace)
// It's just tailored aroun the need of an executor and should be quite generic
// to work with multiple implementations. For example:
// * Docker containers
// * Kubernetes pods
// * A Virtual Machine on which we execute multiple processes
type Driver interface {
	Setup(ctx context.Context) error
	NewPod(ctx context.Context, podConfig *PodConfig, out io.Writer) (Pod, error)
	GetPods(ctx context.Context, all bool) ([]Pod, error)
	ExecutorGroup(ctx context.Context) (string, error)
	GetExecutors(ctx context.Context) ([]string, error)
	Archs(ctx context.Context) ([]types.Arch, error)
}

type Pod interface {
	// ID returns the pod id
	ID() string
	// ExecutorID return the pod owner executor id
	ExecutorID() string
	// TaskID return the pod task id
	TaskID() string
	// Stop stops the pod
	Stop(ctx context.Context) error
	// Stop stops the pod
	Remove(ctx context.Context) error
	// Exec executes a command inside the first container in the Pod
	Exec(ctx context.Context, execConfig *ExecConfig) (ContainerExec, error)
}

type ContainerExec interface {
	Stdin() io.WriteCloser
	Wait(ctx context.Context) (int, error)
}

type PodConfig struct {
	ID         string
	TaskID     string
	Containers []*ContainerConfig
	Arch       types.Arch
	// The container dir where the init volume will be mounted
	InitVolumeDir string
	DockerConfig  *registry.DockerConfig
}

type ContainerConfig struct {
	Cmd        []string
	Env        map[string]string
	WorkingDir string
	Image      string
	User       string
	Privileged bool
	Volumes    []Volume
}

type Volume struct {
	Path string

	TmpFS *VolumeTmpFS
}

type VolumeTmpFS struct {
	Size int64
}

type ExecConfig struct {
	Cmd         []string
	Env         map[string]string
	WorkingDir  string
	User        string
	AttachStdin bool
	Stdout      io.Writer
	Stderr      io.Writer
	Tty         bool
}

func toolboxExecPath(toolboxDir string, arch types.Arch) (string, error) {
	toolboxPath := filepath.Join(toolboxDir, fmt.Sprintf("%s-linux-%s", toolboxPrefix, arch))
	_, err := os.Stat(toolboxPath)
	if err != nil {
		return "", err
	}
	return toolboxPath, nil
}
