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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	errors "golang.org/x/xerrors"
	"github.com/sorintlab/agola/internal/common"
	"github.com/sorintlab/agola/internal/services/executor/registry"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/stdcopy"
	"go.uber.org/zap"
)

type DockerDriver struct {
	log               *zap.SugaredLogger
	client            *client.Client
	initVolumeHostDir string
	toolboxPath       string
	executorID        string
	arch              common.Arch
}

func NewDockerDriver(logger *zap.Logger, executorID, initVolumeHostDir, toolboxPath string) (*DockerDriver, error) {
	cli, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}

	return &DockerDriver{
		log:               logger.Sugar(),
		client:            cli,
		initVolumeHostDir: initVolumeHostDir,
		toolboxPath:       toolboxPath,
		executorID:        executorID,
		arch:              common.ArchFromString(runtime.GOARCH),
	}, nil
}

func (d *DockerDriver) Setup(ctx context.Context) error {
	return d.CopyToolbox(ctx)
}

// CopyToolbox is an hack needed when running the executor inside a docker
// container. It copies the agola-toolbox binaries from the container to an
// host path so it can be bind mounted to the other containers
func (d *DockerDriver) CopyToolbox(ctx context.Context) error {
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

	toolboxExecPath, err := toolboxExecPath(d.toolboxPath, d.arch)
	if err != nil {
		return errors.Errorf("failed to get toolbox path for arch %q: %w", d.arch, err)
	}
	srcInfo, err := archive.CopyInfoSourcePath(toolboxExecPath, false)
	if err != nil {
		return err
	}
	srcInfo.RebaseName = "agola-toolbox"

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

func (d *DockerDriver) Archs(ctx context.Context) ([]common.Arch, error) {
	// since we are using the local docker driver we can return our go arch information
	return []common.Arch{d.arch}, nil
}

func (d *DockerDriver) NewPod(ctx context.Context, podConfig *PodConfig, out io.Writer) (Pod, error) {
	if len(podConfig.Containers) == 0 {
		return nil, errors.Errorf("empty container config")
	}

	var mainContainerID string
	for cindex := range podConfig.Containers {
		resp, err := d.createContainer(ctx, cindex, podConfig, mainContainerID, out)
		if err != nil {
			return nil, err
		}

		containerID := resp.ID
		if cindex == 0 {
			// save the maincontainerid
			mainContainerID = containerID
		}

		if err := d.client.ContainerStart(ctx, containerID, types.ContainerStartOptions{}); err != nil {
			return nil, err
		}
	}

	searchLabels := map[string]string{}
	searchLabels[agolaLabelKey] = agolaLabelValue
	searchLabels[podIDKey] = podConfig.ID
	searchLabels[taskIDKey] = podConfig.TaskID
	args := filters.NewArgs()
	for k, v := range searchLabels {
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
		return nil, errors.Errorf("no container with labels %s", searchLabels)
	}

	pod := &DockerPod{
		id:         podConfig.ID,
		client:     d.client,
		executorID: d.executorID,
		containers: []*DockerContainer{},
	}

	count := 0
	seenIndexes := map[int]struct{}{}
	for _, container := range containers {
		cIndexStr, ok := container.Labels[containerIndexKey]
		if !ok {
			// ignore container
			continue
		}
		cIndex, err := strconv.Atoi(cIndexStr)
		if err != nil {
			// ignore container
			continue
		}
		if _, ok := seenIndexes[cIndex]; ok {
			return nil, errors.Errorf("duplicate container with index %d", cIndex)
		}
		dContainer := &DockerContainer{
			Index:     cIndex,
			Container: container,
		}
		pod.containers = append(pod.containers, dContainer)

		seenIndexes[cIndex] = struct{}{}
		count++
	}
	if count != len(containers) {
		return nil, errors.Errorf("expected %d containers but got %d", len(containers), count)
	}
	// put the containers in the right order based on their container index
	sort.Sort(ContainerSlice(pod.containers))

	return pod, nil
}

func (d *DockerDriver) fetchImage(ctx context.Context, image string, registryConfig *registry.DockerConfig, out io.Writer) error {
	regName, err := registry.GetRegistry(image)
	if err != nil {
		return err
	}
	var registryAuth registry.DockerConfigAuth
	if registryConfig != nil {
		if regauth, ok := registryConfig.Auths[regName]; ok {
			registryAuth = regauth
		}
	}
	buf, err := json.Marshal(registryAuth)
	if err != nil {
		return err
	}
	registryAuthEnc := base64.URLEncoding.EncodeToString(buf)

	// by default always try to pull the image so we are sure only authorized users can fetch them
	// see https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#alwayspullimages
	reader, err := d.client.ImagePull(ctx, image, types.ImagePullOptions{RegistryAuth: registryAuthEnc})
	if err != nil {
		return err
	}

	_, err = io.Copy(out, reader)
	return err
}

func (d *DockerDriver) createContainer(ctx context.Context, index int, podConfig *PodConfig, maincontainerID string, out io.Writer) (*container.ContainerCreateCreatedBody, error) {
	containerConfig := podConfig.Containers[index]

	if err := d.fetchImage(ctx, containerConfig.Image, podConfig.DockerConfig, out); err != nil {
		return nil, err
	}

	labels := map[string]string{}
	labels[agolaLabelKey] = agolaLabelValue
	labels[podIDKey] = podConfig.ID
	labels[taskIDKey] = podConfig.TaskID

	containerLabels := map[string]string{}
	for k, v := range labels {
		containerLabels[k] = v
	}
	containerLabels[containerIndexKey] = strconv.Itoa(index)

	cliContainerConfig := &container.Config{
		Entrypoint: containerConfig.Cmd,
		Env:        makeEnvSlice(containerConfig.Env),
		WorkingDir: containerConfig.WorkingDir,
		Image:      containerConfig.Image,
		Tty:        true,
		Labels:     containerLabels,
	}

	cliHostConfig := &container.HostConfig{
		Privileged: containerConfig.Privileged,
	}
	if index == 0 {
		// main container requires the initvolume containing the toolbox
		cliHostConfig.Binds = []string{fmt.Sprintf("%s:%s", d.initVolumeHostDir, podConfig.InitVolumeDir)}
		cliHostConfig.ReadonlyPaths = []string{fmt.Sprintf("%s:%s", d.initVolumeHostDir, podConfig.InitVolumeDir)}
	} else {
		// attach other containers to maincontainer network
		cliHostConfig.NetworkMode = container.NetworkMode(fmt.Sprintf("container:%s", maincontainerID))
	}

	resp, err := d.client.ContainerCreate(ctx, cliContainerConfig, cliHostConfig, nil, "")
	return &resp, err
}

func (d *DockerDriver) ExecutorGroup(ctx context.Context) (string, error) {
	// use the same group as the executor id
	return d.executorID, nil
}

func (d *DockerDriver) GetExecutors(ctx context.Context) ([]string, error) {
	return []string{d.executorID}, nil
}

func (d *DockerDriver) GetPods(ctx context.Context, all bool) ([]Pod, error) {
	args := filters.NewArgs()

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
		if _, ok := podsMap[podID]; !ok {
			pod := &DockerPod{
				id:         podID,
				client:     d.client,
				executorID: d.executorID,
				containers: []*DockerContainer{},
			}
			podsMap[podID] = pod
		}
	}

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
		dContainer := &DockerContainer{
			Index:     cIndex,
			Container: container,
		}
		pod.containers = append(pod.containers, dContainer)

		// overwrite containers with the right order

		// add labels from the container with index 0
		if cIndex == 0 {
			podLabels := map[string]string{}
			// keep only labels starting with our prefix
			for labelName, labelValue := range container.Labels {
				if strings.HasPrefix(labelName, labelPrefix) {
					podLabels[labelName] = labelValue
				}
			}
			pod.labels = podLabels
		}
	}

	pods := make([]Pod, 0, len(podsMap))
	for _, pod := range podsMap {
		// put the containers in the right order based on their container index
		sort.Sort(ContainerSlice(pod.containers))
		pods = append(pods, pod)
	}
	return pods, nil
}

func podLabelsFromContainer(containerLabels map[string]string) map[string]string {
	labels := map[string]string{}
	// keep only labels starting with our prefix
	for k, v := range containerLabels {
		if strings.HasPrefix(k, labelPrefix) {
			labels[k] = v
		}
	}
	return labels
}

type DockerPod struct {
	id         string
	client     *client.Client
	labels     map[string]string
	containers []*DockerContainer
	executorID string
}

type DockerContainer struct {
	Index int
	types.Container
}

type ContainerSlice []*DockerContainer

func (p ContainerSlice) Len() int           { return len(p) }
func (p ContainerSlice) Less(i, j int) bool { return p[i].Index < p[j].Index }
func (p ContainerSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func (dp *DockerPod) ID() string {
	return dp.id
}

func (dp *DockerPod) ExecutorID() string {
	return dp.executorID
}

func (dp *DockerPod) TaskID() string {
	return dp.labels[taskIDKey]
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

func (dp *DockerPod) Exec(ctx context.Context, execConfig *ExecConfig) (ContainerExec, error) {
	endCh := make(chan error)

	dockerExecConfig := types.ExecConfig{
		Cmd:          execConfig.Cmd,
		Env:          makeEnvSlice(execConfig.Env),
		Tty:          execConfig.Tty,
		WorkingDir:   execConfig.WorkingDir,
		AttachStdin:  execConfig.AttachStdin,
		AttachStdout: execConfig.Stdout != nil,
		AttachStderr: execConfig.Stderr != nil,
		User:         execConfig.User,
	}

	response, err := dp.client.ContainerExecCreate(ctx, dp.containers[0].ID, dockerExecConfig)
	if err != nil {
		return nil, err
	}
	execStartCheck := types.ExecStartCheck{
		Detach: dockerExecConfig.Detach,
		Tty:    dockerExecConfig.Tty,
	}
	hresp, err := dp.client.ContainerExecAttach(ctx, response.ID, execStartCheck)
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
		client: dp.client,
		stdin:  stdin,
		endCh:  endCh,
	}, nil
}

func (e *DockerContainerExec) Wait(ctx context.Context) (int, error) {
	// ignore error, we'll use the exit code of the exec
	<-e.endCh

	var exitCode int
	for {
		resp, err := e.client.ContainerExecInspect(ctx, e.execID)
		if err != nil {
			return -1, err
		}
		if !resp.Running {
			exitCode = resp.ExitCode
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	e.hresp.Close()

	return exitCode, nil
}

func (e *DockerContainerExec) Stdin() io.WriteCloser {
	return e.stdin
}

func makeEnvSlice(env map[string]string) []string {
	envList := make([]string, 0, len(env))
	for k, v := range env {
		envList = append(envList, fmt.Sprintf("%s=%s", k, v))
	}

	return envList
}
