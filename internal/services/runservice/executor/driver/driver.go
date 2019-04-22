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
	"io"

	"github.com/sorintlab/agola/internal/services/runservice/executor/registry"
)

const (
	agolaLabelKey   = "agola"
	agolaLabelValue = "true"

	podIDKey          = "podID"
	containerIndexKey = "index"
	taskKey           = "task"

	podLabelPrefix = "podlabel_"
)

// Driver is a generic interface around the pod concept (a group of "containers"
// sharing, at least, the same network namespace)
// It's just tailored aroun the need of an executor and should be quite generic
// to work with multiple implementations. For example:
// * Docker containers
// * Kubernetes pods
// * A Virtual Machine on which we execute multiple processes
type Driver interface {
	NewPod(ctx context.Context, podConfig *PodConfig, out io.Writer) (Pod, error)
	GetPodsByLabels(ctx context.Context, labels map[string]string, all bool) ([]Pod, error)
	GetPodByID(ctx context.Context, containerID string) (Pod, error)
}

type Pod interface {
	// ID returns the pod id
	ID() string
	// Labels returns the pod labels
	Labels() map[string]string
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
	Containers []*ContainerConfig
	Labels     map[string]string
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
}

type ExecConfig struct {
	Cmd        []string
	Env        map[string]string
	WorkingDir string
	User       string
	Stdout     io.Writer
	Stderr     io.Writer
	Tty        bool
}
