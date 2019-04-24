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
	"context"
	"io"

	"github.com/sorintlab/agola/internal/services/runservice/executor/registry"
)

const (
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
	GetPodByID(ctx context.Context, containerID string) (Pod, error)
	ExecutorGroup(ctx context.Context) (string, error)
	GetExecutors(ctx context.Context) ([]string, error)
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
