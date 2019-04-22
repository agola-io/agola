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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sorintlab/agola/internal/services/runservice/executor/registry"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/stdcopy"
	"go.uber.org/zap"
)

type DockerDriver struct {
	logger            *zap.Logger
	client            *client.Client
	initVolumeHostDir string
}

func NewDockerDriver(logger *zap.Logger, initVolumeHostDir string) (*DockerDriver, error) {
	cli, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}
	return &DockerDriver{
		logger:            logger,
		client:            cli,
		initVolumeHostDir: initVolumeHostDir,
	}, nil
}

// CopyToolbox is an hack needed when running the executor inside a docker
// container. It copies the agola-toolbox binaries from the container to an
// host path so it can be bind mounted to the other containers
func (d *DockerDriver) CopyToolbox(ctx context.Context, toolboxPath string) error {
	// by default always try to pull the image so we are sure only authorized users can fetch them
	// see https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#alwayspullimages
	reader, err := d.client.ImagePull(ctx, "busybox", types.ImagePullOptions{})
	if err != nil {
		return err
	}
	io.Copy(os.Stdout, reader)

	resp, err := d.client.ContainerCreate(ctx, &container.Config{
		Entrypoint: []string{"cat"},
		Image:      "busybox",
		Tty:        true,
	}, &container.HostConfig{
		Binds: []string{fmt.Sprintf("%s:%s", d.initVolumeHostDir, "/tmp/agola")},
	}, nil, "")
	if err != nil {
		return err
	}

	containerID := resp.ID

	if err := d.client.ContainerStart(ctx, containerID, types.ContainerStartOptions{}); err != nil {
		return err
	}

	srcInfo, err := archive.CopyInfoSourcePath(toolboxPath, false)
	if err != nil {
		return err
	}

	srcArchive, err := archive.TarResource(srcInfo)
	if err != nil {
		return err
	}
	defer srcArchive.Close()

	options := types.CopyToContainerOptions{
		AllowOverwriteDirWithFile: false,
		CopyUIDGID:                false,
	}

	if err := d.client.CopyToContainer(ctx, containerID, "/tmp/agola", srcArchive, options); err != nil {
		return err
	}

	// ignore remove error
	d.client.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{Force: true})

	return nil
}

func (d *DockerDriver) NewPod(ctx context.Context, podConfig *PodConfig, out io.Writer) (Pod, error) {
	if len(podConfig.Containers) == 0 {
		return nil, errors.Errorf("empty container config")
	}

	containerConfig := podConfig.Containers[0]

	regName, err := registry.GetRegistry(containerConfig.Image)
	if err != nil {
		return nil, err
	}
	var registryAuth registry.DockerConfigAuth
	if podConfig.DockerConfig != nil {
		if regauth, ok := podConfig.DockerConfig.Auths[regName]; ok {
			registryAuth = regauth
		}
	}
	buf, err := json.Marshal(registryAuth)
	if err != nil {
		return nil, err
	}
	registryAuthEnc := base64.URLEncoding.EncodeToString(buf)

	// by default always try to pull the image so we are sure only authorized users can fetch them
	// see https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#alwayspullimages
	reader, err := d.client.ImagePull(ctx, containerConfig.Image, types.ImagePullOptions{RegistryAuth: registryAuthEnc})
	if err != nil {
		return nil, err
	}
	io.Copy(out, reader)

	labels := map[string]string{}
	// prepend the podLabelPrefix to the labels' keys
	for k, v := range podConfig.Labels {
		labels[podLabelPrefix+k] = v
	}
	labels[agolaLabelKey] = agolaLabelValue
	labels[podIDKey] = podConfig.ID

	containerLabels := map[string]string{}
	for k, v := range labels {
		containerLabels[k] = v
	}
	containerLabels[containerIndexKey] = "0"

	resp, err := d.client.ContainerCreate(ctx, &container.Config{
		Entrypoint: containerConfig.Cmd,
		Env:        makeEnv(containerConfig.Env),
		WorkingDir: containerConfig.WorkingDir,
		Image:      containerConfig.Image,
		Tty:        true,
		Labels:     containerLabels,
	}, &container.HostConfig{
		Binds:         []string{fmt.Sprintf("%s:%s", d.initVolumeHostDir, podConfig.InitVolumeDir)},
		ReadonlyPaths: []string{fmt.Sprintf("%s:%s", d.initVolumeHostDir, podConfig.InitVolumeDir)},
		Privileged:    containerConfig.Privileged,
	}, nil, "")
	if err != nil {
		return nil, err
	}

	containerID := resp.ID

	if err := d.client.ContainerStart(ctx, containerID, types.ContainerStartOptions{}); err != nil {
		return nil, err
	}

	args := filters.NewArgs()
	for k, v := range labels {
		args.Add("label", fmt.Sprintf("%s=%s", k, v))
	}

	containers, err := d.client.ContainerList(ctx,
		types.ContainerListOptions{
			Filters: args,
		})
	if err != nil {
		return nil, err
	}
	if len(containers) == 0 {
		return nil, errors.Errorf("no container with id %s", containerID)
	}

	return &DockerPod{
		id:         podConfig.ID,
		client:     d.client,
		containers: containers,
	}, nil
}

func (d *DockerDriver) GetPodsByLabels(ctx context.Context, labels map[string]string, all bool) ([]Pod, error) {
	args := filters.NewArgs()
	// search label adding the podLabelPrefix
	for k, v := range labels {
		args.Add("label", fmt.Sprintf("%s%s=%s", podLabelPrefix, k, v))
	}

	containers, err := d.client.ContainerList(ctx,
		types.ContainerListOptions{
			Filters: args,
			All:     all,
		})
	if err != nil {
		return nil, err
	}

	podsMap := map[string]*DockerPod{}
	for _, container := range containers {
		podID, ok := container.Labels[podIDKey]
		if !ok {
			// skip container
			continue
		}
		if pod, ok := podsMap[podID]; !ok {
			pod := &DockerPod{
				id:         podID,
				client:     d.client,
				containers: []types.Container{container},
			}
			podsMap[podID] = pod

		} else {
			pod.containers = append(pod.containers, container)
		}
	}

	// Put the containers in the right order based on their containerIndexKey label value
	for _, container := range containers {
		podID, ok := container.Labels[podIDKey]
		if !ok {
			// skip container
			continue
		}
		cIndexStr, ok := container.Labels[containerIndexKey]
		if !ok {
			// remove pod since some of its containers don't have the right labels
			delete(podsMap, podID)
		}
		cIndex, err := strconv.Atoi(cIndexStr)
		if err != nil {
			// remove pod since some of its containers don't have the right labels
			delete(podsMap, podID)
		}
		pod := podsMap[podID]
		pod.containers[cIndex] = container

		// overwrite containers with the right order

		// add labels from the container with index 0
		if cIndex == 0 {
			podLabels := map[string]string{}
			for labelName, labelValue := range container.Labels {
				if strings.HasPrefix(labelName, podLabelPrefix) {
					podLabels[strings.TrimPrefix(labelName, podLabelPrefix)] = labelValue
				}
			}
			pod.labels = podLabels
		}
	}

	pods := make([]Pod, 0, len(podsMap))
	for _, pod := range podsMap {
		pods = append(pods, pod)
	}
	return pods, nil
}

func podLabelsFromContainer(containerLabels map[string]string) map[string]string {
	labels := map[string]string{}
	for k, v := range containerLabels {
		if strings.HasPrefix(k, podLabelPrefix) {
			labels[strings.TrimPrefix(k, podLabelPrefix)] = v
		}
	}
	return labels
}

func (d *DockerDriver) GetPodByID(ctx context.Context, containerID string) (Pod, error) {
	args := filters.NewArgs()
	args.Add(podIDKey, containerID)

	containers, err := d.client.ContainerList(ctx,
		types.ContainerListOptions{
			Filters: args,
		})
	if err != nil {
		return nil, err
	}
	if len(containers) == 0 {
		return nil, errors.Errorf("no container with id %s", containerID)
	}

	return &DockerPod{
		labels:     podLabelsFromContainer(containers[0].Labels),
		client:     d.client,
		containers: containers,
	}, nil
}

type DockerPod struct {
	id         string
	client     *client.Client
	labels     map[string]string
	containers []types.Container
}

func (dp *DockerPod) ID() string {
	return dp.id
}

func (dp *DockerPod) Labels() map[string]string {
	return dp.labels
}

func (dp *DockerPod) Stop(ctx context.Context) error {
	d := 1 * time.Second
	errs := []error{}
	for _, container := range dp.containers {
		if err := dp.client.ContainerStop(ctx, container.ID, &d); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return errors.Errorf("stop errors: %v", errs)
	}
	return nil
}

func (dp *DockerPod) Remove(ctx context.Context) error {
	errs := []error{}
	for _, container := range dp.containers {
		if err := dp.client.ContainerRemove(ctx, container.ID, types.ContainerRemoveOptions{Force: true}); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return errors.Errorf("remove errors: %v", errs)
	}
	return nil
}

type DockerContainerExec struct {
	execID string
	hresp  *types.HijackedResponse
	client *client.Client
	endCh  chan error

	stdin io.WriteCloser
}

// Stdin is a wrapped HikackedResponse implementing io.WriteCloser so users can
// easily close stdin. Internally it will close only the write side of the conn.
type Stdin struct {
	hresp *types.HijackedResponse
}

func (s *Stdin) Write(p []byte) (int, error) {
	return s.hresp.Conn.Write(p)
}

func (s *Stdin) Close() error {
	return s.hresp.CloseWrite()
}

func (dc *DockerPod) Exec(ctx context.Context, execConfig *ExecConfig) (ContainerExec, error) {
	endCh := make(chan error)

	dockerExecConfig := types.ExecConfig{
		Cmd:          execConfig.Cmd,
		Env:          makeEnv(execConfig.Env),
		Tty:          execConfig.Tty,
		WorkingDir:   execConfig.WorkingDir,
		AttachStdin:  true,
		AttachStdout: execConfig.Stdout != nil,
		AttachStderr: execConfig.Stderr != nil,
		User:         execConfig.User,
	}

	response, err := dc.client.ContainerExecCreate(ctx, dc.containers[0].ID, dockerExecConfig)
	if err != nil {
		return nil, err
	}
	execStartCheck := types.ExecStartCheck{
		Detach: dockerExecConfig.Detach,
		Tty:    dockerExecConfig.Tty,
	}
	hresp, err := dc.client.ContainerExecAttach(ctx, response.ID, execStartCheck)
	if err != nil {
		return nil, err
	}

	stdout := execConfig.Stdout
	stderr := execConfig.Stderr
	if execConfig.Stdout == nil {
		stdout = ioutil.Discard
	}
	if execConfig.Stderr == nil {
		stderr = ioutil.Discard
	}

	// copy both stdout and stderr to out file
	go func() {
		var err error
		if execConfig.Tty {
			_, err = io.Copy(stdout, hresp.Reader)
		} else {
			_, err = stdcopy.StdCopy(stdout, stderr, hresp.Reader)
		}
		endCh <- err
	}()

	stdin := &Stdin{
		hresp: &hresp,
	}

	return &DockerContainerExec{
		execID: response.ID,
		hresp:  &hresp,
		client: dc.client,
		stdin:  stdin,
		endCh:  endCh,
	}, nil
}

func (e *DockerContainerExec) Wait(ctx context.Context) (int, error) {
	// ignore error, we'll use the exit code of the exec
	<-e.endCh

	resp, err := e.client.ContainerExecInspect(ctx, e.execID)
	if err != nil {
		return -1, err
	}
	exitCode := resp.ExitCode

	e.hresp.Close()

	return exitCode, nil
}

func (e *DockerContainerExec) Stdin() io.WriteCloser {
	return e.stdin
}

func makeEnv(env map[string]string) []string {
	envList := make([]string, 0, len(env))
	for k, v := range env {
		envList = append(envList, fmt.Sprintf("%s=%s", k, v))
	}

	return envList
}
