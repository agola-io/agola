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

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	uuid "github.com/satori/go.uuid"
	"github.com/sorintlab/agola/internal/common"
	slog "github.com/sorintlab/agola/internal/log"
	"github.com/sorintlab/agola/internal/services/config"
	"github.com/sorintlab/agola/internal/services/executor/driver"
	"github.com/sorintlab/agola/internal/services/executor/registry"
	rsapi "github.com/sorintlab/agola/internal/services/runservice/api"
	"github.com/sorintlab/agola/internal/services/runservice/types"
	"github.com/sorintlab/agola/internal/util"

	"github.com/gorilla/mux"
	sockaddr "github.com/hashicorp/go-sockaddr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	errors "golang.org/x/xerrors"
)

var level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
var logger = slog.New(level)
var log = logger.Sugar()

const (
	defaultShell = "/bin/sh -e"

	toolboxContainerDir = "/mnt/agola"
)

var (
	toolboxContainerPath = filepath.Join(toolboxContainerDir, "/agola-toolbox")
)

func (e *Executor) getAllPods(ctx context.Context, all bool) ([]driver.Pod, error) {
	return e.driver.GetPods(ctx, all)
}

func (e *Executor) createFile(ctx context.Context, pod driver.Pod, command, user string, outf io.Writer) (string, error) {
	cmd := []string{toolboxContainerPath, "createfile"}

	var buf bytes.Buffer
	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		AttachStdin: true,
		Stdout:      &buf,
		Stderr:      outf,
		User:        user,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return "", err
	}

	stdin := ce.Stdin()
	go func() {
		io.WriteString(stdin, command)
		io.WriteString(stdin, "\n")
		stdin.Close()
	}()

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return "", err
	}
	if exitCode != 0 {
		return "", errors.Errorf("toolbox exited with code: %d", exitCode)
	}

	return buf.String(), nil
}

func (e *Executor) doRunStep(ctx context.Context, s *types.RunStep, t *types.ExecutorTask, pod driver.Pod, logPath string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0770); err != nil {
		return -1, err
	}
	outf, err := os.Create(logPath)
	if err != nil {
		return -1, err
	}
	defer outf.Close()

	shell := defaultShell
	if t.Shell != "" {
		shell = t.Shell
	}
	if s.Shell != "" {
		shell = s.Shell
	}

	// try to use the container specified user
	user := t.Containers[0].User
	if t.User != "" {
		user = t.User
	}
	if s.User != "" {
		user = s.User
	}

	var cmd []string
	if s.Command != "" {
		filename, err := e.createFile(ctx, pod, s.Command, user, outf)
		if err != nil {
			return -1, errors.Errorf("create file err: %v", err)
		}

		args := strings.Split(shell, " ")
		cmd = append(args, filename)
	} else {
		cmd = strings.Split(shell, " ")
	}

	// override task working dir with runstep working dir if provided
	workingDir := t.WorkingDir
	if s.WorkingDir != "" {
		workingDir = s.WorkingDir
	}

	// generate the environment using the task environment and then overriding with the runstep environment
	environment := map[string]string{}
	for envName, envValue := range t.Environment {
		environment[envName] = envValue
	}
	for envName, envValue := range s.Environment {
		environment[envName] = envValue
	}

	workingDir, err = e.expandDir(ctx, t, pod, outf, workingDir)
	if err != nil {
		outf.WriteString(fmt.Sprintf("failed to expand working dir %q. Error: %s\n", workingDir, err))
		return -1, err
	}

	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		Env:         environment,
		WorkingDir:  workingDir,
		User:        user,
		AttachStdin: true,
		Stdout:      outf,
		Stderr:      outf,
		Tty:         true,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return -1, err
	}

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return -1, err
	}

	return exitCode, nil
}

func (e *Executor) doSaveToWorkspaceStep(ctx context.Context, s *types.SaveToWorkspaceStep, t *types.ExecutorTask, pod driver.Pod, logPath string, archivePath string) (int, error) {
	cmd := []string{toolboxContainerPath, "archive"}

	if err := os.MkdirAll(filepath.Dir(logPath), 0770); err != nil {
		return -1, err
	}
	logf, err := os.Create(logPath)
	if err != nil {
		return -1, err
	}
	defer logf.Close()

	if err := os.MkdirAll(filepath.Dir(archivePath), 0770); err != nil {
		return -1, err
	}
	archivef, err := os.Create(archivePath)
	if err != nil {
		return -1, err
	}
	defer archivef.Close()

	workingDir, err := e.expandDir(ctx, t, pod, logf, t.WorkingDir)
	if err != nil {
		logf.WriteString(fmt.Sprintf("failed to expand working dir %q. Error: %s\n", t.WorkingDir, err))
		return -1, err
	}

	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		Env:         t.Environment,
		WorkingDir:  workingDir,
		AttachStdin: true,
		Stdout:      archivef,
		Stderr:      logf,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return -1, err
	}

	type ArchiveInfo struct {
		SourceDir string
		DestDir   string
		Paths     []string
	}
	type Archive struct {
		ArchiveInfos []*ArchiveInfo
		OutFile      string
	}

	a := &Archive{
		OutFile:      "", // use stdout
		ArchiveInfos: make([]*ArchiveInfo, len(s.Contents)),
	}

	for i, c := range s.Contents {
		a.ArchiveInfos[i] = &ArchiveInfo{
			SourceDir: c.SourceDir,
			DestDir:   c.DestDir,
			Paths:     c.Paths,
		}

	}

	stdin := ce.Stdin()
	enc := json.NewEncoder(stdin)

	go func() {
		enc.Encode(a)
		stdin.Close()
	}()

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return -1, err
	}

	return exitCode, nil
}

func (e *Executor) expandDir(ctx context.Context, t *types.ExecutorTask, pod driver.Pod, logf io.Writer, dir string) (string, error) {
	args := []string{dir}
	cmd := append([]string{toolboxContainerPath, "expanddir"}, args...)

	// limit the template answer to max 1MiB
	stdout := &bytes.Buffer{}

	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		Env:         t.Environment,
		AttachStdin: true,
		Stdout:      stdout,
		Stderr:      logf,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return "", err
	}

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return "", err
	}
	if exitCode != 0 {
		return "", errors.Errorf("expanddir ended with exit code %d", exitCode)
	}

	return stdout.String(), nil
}

func (e *Executor) mkdir(ctx context.Context, t *types.ExecutorTask, pod driver.Pod, logf io.Writer, dir string) error {
	args := []string{dir}
	cmd := append([]string{toolboxContainerPath, "mkdir"}, args...)

	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		Env:         t.Environment,
		AttachStdin: true,
		Stdout:      logf,
		Stderr:      logf,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return err
	}

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return errors.Errorf("mkdir ended with exit code %d", exitCode)
	}

	return nil
}

func (e *Executor) template(ctx context.Context, t *types.ExecutorTask, pod driver.Pod, logf io.Writer, key string) (string, error) {
	cmd := append([]string{toolboxContainerPath, "template"})

	// limit the template answer to max 1MiB
	stdout := util.NewLimitedBuffer(1024 * 1024)

	workingDir, err := e.expandDir(ctx, t, pod, logf, t.WorkingDir)
	if err != nil {
		io.WriteString(logf, fmt.Sprintf("failed to expand working dir %q. Error: %s\n", t.WorkingDir, err))
		return "", err
	}

	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		Env:         t.Environment,
		WorkingDir:  workingDir,
		AttachStdin: true,
		Stdout:      stdout,
		Stderr:      logf,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return "", err
	}

	stdin := ce.Stdin()
	go func() {
		io.WriteString(stdin, key)
		stdin.Close()
	}()

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return "", err
	}
	if exitCode != 0 {
		return "", errors.Errorf("template ended with exit code %d", exitCode)
	}

	return stdout.String(), nil
}

func (e *Executor) unarchive(ctx context.Context, t *types.ExecutorTask, source io.Reader, pod driver.Pod, logf io.Writer, destDir string, overwrite, removeDestDir bool) error {
	args := []string{"--destdir", destDir}
	if overwrite {
		args = append(args, "--overwrite")
	}
	if removeDestDir {
		args = append(args, "--remove-destdir")
	}
	cmd := append([]string{toolboxContainerPath, "unarchive"}, args...)

	workingDir, err := e.expandDir(ctx, t, pod, logf, t.WorkingDir)
	if err != nil {
		io.WriteString(logf, fmt.Sprintf("failed to expand working dir %q. Error: %s\n", t.WorkingDir, err))
		return err
	}

	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		Env:         t.Environment,
		WorkingDir:  workingDir,
		AttachStdin: true,
		Stdout:      logf,
		Stderr:      logf,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return err
	}

	stdin := ce.Stdin()
	go func() {
		io.Copy(stdin, source)
		stdin.Close()
	}()

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return errors.Errorf("unarchive ended with exit code %d", exitCode)
	}

	return nil
}

func (e *Executor) doRestoreWorkspaceStep(ctx context.Context, s *types.RestoreWorkspaceStep, t *types.ExecutorTask, pod driver.Pod, logPath string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0770); err != nil {
		return -1, err
	}
	logf, err := os.Create(logPath)
	if err != nil {
		return -1, err
	}
	defer logf.Close()

	for _, op := range t.WorkspaceOperations {
		log.Debugf("unarchiving workspace for taskID: %s, step: %d", level, op.TaskID, op.Step)
		resp, err := e.runserviceClient.GetArchive(ctx, op.TaskID, op.Step)
		if err != nil {
			// TODO(sgotti) retry before giving up
			fmt.Fprintf(logf, "error reading workspace archive: %v\n", err)
			return -1, err
		}
		archivef := resp.Body
		if err := e.unarchive(ctx, t, archivef, pod, logf, s.DestDir, false, false); err != nil {
			archivef.Close()
			return -1, err
		}
		archivef.Close()
	}

	return 0, nil
}

func (e *Executor) doSaveCacheStep(ctx context.Context, s *types.SaveCacheStep, t *types.ExecutorTask, pod driver.Pod, logPath string, archivePath string) (int, error) {
	cmd := []string{toolboxContainerPath, "archive"}

	if err := os.MkdirAll(filepath.Dir(logPath), 0770); err != nil {
		return -1, err
	}
	logf, err := os.Create(logPath)
	if err != nil {
		return -1, err
	}
	defer logf.Close()

	save := false

	// calculate key from template
	userKey, err := e.template(ctx, t, pod, logf, s.Key)
	if err != nil {
		return -1, err
	}
	fmt.Fprintf(logf, "cache key %q\n", userKey)

	// append cache prefix
	key := t.CachePrefix + "-" + userKey

	// check that the cache key doesn't already exists
	resp, err := e.runserviceClient.CheckCache(ctx, key, false)
	if err != nil {
		// ignore 404 errors since they means that the cache key doesn't exists
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			fmt.Fprintf(logf, "no cache available for key %q. Saving.\n", userKey)
			save = true
		} else {
			// TODO(sgotti) retry before giving up
			fmt.Fprintf(logf, "error checking for cache key %q: %v\n", userKey, err)
			return -1, err
		}
	}
	if !save {
		fmt.Fprintf(logf, "cache for key %q already exists\n", userKey)
		return 0, nil
	}

	fmt.Fprintf(logf, "archiving cache with key %q\n", userKey)
	if err := os.MkdirAll(filepath.Dir(archivePath), 0770); err != nil {
		return -1, err
	}
	archivef, err := os.Create(archivePath)
	if err != nil {
		return -1, err
	}
	defer archivef.Close()

	workingDir, err := e.expandDir(ctx, t, pod, logf, t.WorkingDir)
	if err != nil {
		io.WriteString(logf, fmt.Sprintf("failed to expand working dir %q. Error: %s\n", t.WorkingDir, err))
		return -1, err
	}

	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		Env:         t.Environment,
		WorkingDir:  workingDir,
		AttachStdin: true,
		Stdout:      archivef,
		Stderr:      logf,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return -1, err
	}

	type ArchiveInfo struct {
		SourceDir string
		DestDir   string
		Paths     []string
	}
	type Archive struct {
		ArchiveInfos []*ArchiveInfo
		OutFile      string
	}

	a := &Archive{
		OutFile:      "", // use stdout
		ArchiveInfos: make([]*ArchiveInfo, len(s.Contents)),
	}

	for i, c := range s.Contents {
		a.ArchiveInfos[i] = &ArchiveInfo{
			SourceDir: c.SourceDir,
			DestDir:   c.DestDir,
			Paths:     c.Paths,
		}

	}

	stdin := ce.Stdin()
	enc := json.NewEncoder(stdin)

	go func() {
		enc.Encode(a)
		stdin.Close()
	}()

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return -1, err
	}

	if exitCode != 0 {
		return exitCode, errors.Errorf("save cache archiving command ended with exit code %d", exitCode)
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return -1, err
	}
	fi, err := f.Stat()
	if err != nil {
		return -1, err
	}

	// send cache archive to scheduler
	if resp, err := e.runserviceClient.PutCache(ctx, key, fi.Size(), f); err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotModified {
			return exitCode, nil
		}
		return -1, err
	}

	return exitCode, nil
}

func (e *Executor) doRestoreCacheStep(ctx context.Context, s *types.RestoreCacheStep, t *types.ExecutorTask, pod driver.Pod, logPath string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0770); err != nil {
		return -1, err
	}
	logf, err := os.Create(logPath)
	if err != nil {
		return -1, err
	}
	defer logf.Close()

	fmt.Fprintf(logf, "restoring cache: %s\n", util.Dump(s))
	for _, key := range s.Keys {
		// calculate key from template
		userKey, err := e.template(ctx, t, pod, logf, key)
		if err != nil {
			return -1, err
		}
		fmt.Fprintf(logf, "cache key %q\n", userKey)

		// append cache prefix
		key := t.CachePrefix + "-" + userKey

		resp, err := e.runserviceClient.GetCache(ctx, key, true)
		if err != nil {
			// ignore 404 errors since they means that the cache key doesn't exists
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				fmt.Fprintf(logf, "no cache available for key %q\n", userKey)
				continue
			}
			// TODO(sgotti) retry before giving up
			fmt.Fprintf(logf, "error reading cache: %v\n", err)
			return -1, err
		}
		fmt.Fprintf(logf, "restoring cache with key %q\n", userKey)
		cachef := resp.Body
		if err := e.unarchive(ctx, t, cachef, pod, logf, s.DestDir, false, false); err != nil {
			cachef.Close()
			return -1, err
		}
		cachef.Close()

		// stop here
		break
	}

	return 0, nil
}

func (e *Executor) executorIDPath() string {
	return filepath.Join(e.c.DataDir, "id")
}

func (e *Executor) tasksDir() string {
	return filepath.Join(e.c.DataDir, "tasks")
}

func (e *Executor) taskPath(taskID string) string {
	return filepath.Join(e.tasksDir(), taskID)
}

func (e *Executor) taskLogsPath(taskID string) string {
	return filepath.Join(e.tasksDir(), taskID, "logs")
}

func (e *Executor) setupLogPath(taskID string) string {
	return filepath.Join(e.taskLogsPath(taskID), "setup.log")
}

func (e *Executor) stepLogPath(taskID string, stepID int) string {
	return filepath.Join(e.taskLogsPath(taskID), "steps", fmt.Sprintf("%d.log", stepID))
}

func (e *Executor) archivePath(taskID string, stepID int) string {
	return filepath.Join(e.taskPath(taskID), "archives", fmt.Sprintf("%d.tar", stepID))
}

func (e *Executor) sendExecutorStatus(ctx context.Context) error {
	labels := e.c.Labels
	if labels == nil {
		labels = make(map[string]string)
	}

	activeTasks := e.runningTasks.len()

	archs, err := e.driver.Archs(ctx)
	if err != nil {
		return err
	}

	executorGroup, err := e.driver.ExecutorGroup(ctx)
	if err != nil {
		return err
	}
	// report all the executors that are active OR that have some owned pods not yet removed
	activeExecutors, err := e.driver.GetExecutors(ctx)
	if err != nil {
		return err
	}
	pods, err := e.driver.GetPods(ctx, true)
	if err != nil {
		return err
	}

	executorsMap := map[string]struct{}{}
	for _, executorID := range activeExecutors {
		executorsMap[executorID] = struct{}{}
	}
	for _, pod := range pods {
		executorsMap[pod.ExecutorID()] = struct{}{}
	}
	siblingsExecutors := []string{}
	for executorID := range executorsMap {
		siblingsExecutors = append(siblingsExecutors, executorID)
	}

	executor := &types.Executor{
		ID:                e.id,
		Archs:             archs,
		ListenURL:         e.listenURL,
		Labels:            labels,
		ActiveTasksLimit:  e.c.ActiveTasksLimit,
		ActiveTasks:       activeTasks,
		Dynamic:           e.dynamic,
		ExecutorGroup:     executorGroup,
		SiblingsExecutors: siblingsExecutors,
	}

	log.Debugf("send executor status: %s", util.Dump(executor))
	_, err = e.runserviceClient.SendExecutorStatus(ctx, executor)
	return err
}

func (e *Executor) sendExecutorTaskStatus(ctx context.Context, et *types.ExecutorTask) error {
	log.Debugf("send executor task: %s. status: %s", et.ID, et.Status.Phase)
	_, err := e.runserviceClient.SendExecutorTaskStatus(ctx, e.id, et)
	return err
}

func (e *Executor) stopTask(ctx context.Context, et *types.ExecutorTask) {
	if rt, ok := e.runningTasks.get(et.ID); ok {
		rt.Lock()
		defer rt.Unlock()
		if rt.et.Status.Phase.IsFinished() {
			return
		}
		if rt.pod != nil {
			if err := rt.pod.Stop(ctx); err != nil {
				log.Errorf("err: %+v", err)
				return
			}
			if rt.et.Status.Phase == types.ExecutorTaskPhaseNotStarted {
				rt.et.Status.Phase = types.ExecutorTaskPhaseCancelled
			} else {
				rt.et.Status.Phase = types.ExecutorTaskPhaseStopped
			}
			if err := e.sendExecutorTaskStatus(ctx, et); err != nil {
				log.Errorf("err: %+v", err)
				return
			}
		}
	}
}

func (e *Executor) executeTask(ctx context.Context, et *types.ExecutorTask) {
	// * save in local state that we have a running task
	// * start the pod
	// * then update the executortask status to in-progress
	// if something fails pod will be cleaned up by the pod cleaner goroutine
	// In this way we are sure that the pod cleaner will only remove pod that don't
	// have an in progress running task

	if et.Status.Phase != types.ExecutorTaskPhaseNotStarted {
		log.Debugf("task phase is not \"not started\"")
		return
	}

	activeTasks := e.runningTasks.len()
	// don't start task if we have reached the active tasks limit
	// they will be executed later
	if activeTasks > e.c.ActiveTasksLimit {
		return
	}

	rt := &runningTask{
		et: et,
	}

	rt.Lock()

	if !e.runningTasks.addIfNotExists(et.ID, rt) {
		log.Debugf("task %s already running", et.ID)
		return
	}

	defer e.runningTasks.delete(et.ID)

	et.Status.Phase = types.ExecutorTaskPhaseRunning
	et.Status.StartTime = util.TimePtr(time.Now())
	et.Status.SetupStep.Phase = types.ExecutorTaskPhaseRunning
	et.Status.SetupStep.StartTime = util.TimePtr(time.Now())
	if err := e.sendExecutorTaskStatus(ctx, et); err != nil {
		log.Errorf("err: %+v", err)
	}

	if err := e.setupTask(ctx, rt); err != nil {
		log.Errorf("err: %+v", err)
		rt.et.Status.Phase = types.ExecutorTaskPhaseFailed
		et.Status.SetupStep.EndTime = util.TimePtr(time.Now())
		et.Status.SetupStep.Phase = types.ExecutorTaskPhaseFailed
		et.Status.SetupStep.EndTime = util.TimePtr(time.Now())
		if err := e.sendExecutorTaskStatus(ctx, et); err != nil {
			log.Errorf("err: %+v", err)
		}
		rt.Unlock()
		return
	}

	et.Status.SetupStep.Phase = types.ExecutorTaskPhaseSuccess
	et.Status.SetupStep.EndTime = util.TimePtr(time.Now())
	if err := e.sendExecutorTaskStatus(ctx, et); err != nil {
		log.Errorf("err: %+v", err)
	}

	rt.Unlock()

	_, err := e.executeTaskSteps(ctx, rt, rt.pod)

	rt.Lock()
	if err != nil {
		log.Errorf("err: %+v", err)
		rt.et.Status.Phase = types.ExecutorTaskPhaseFailed
	} else {
		rt.et.Status.Phase = types.ExecutorTaskPhaseSuccess
	}

	rt.et.Status.EndTime = util.TimePtr(time.Now())

	if err := e.sendExecutorTaskStatus(ctx, et); err != nil {
		log.Errorf("err: %+v", err)
	}
	rt.Unlock()
}

func (e *Executor) setupTask(ctx context.Context, rt *runningTask) error {
	et := rt.et
	if err := os.RemoveAll(e.taskPath(et.ID)); err != nil {
		return err
	}
	if err := os.MkdirAll(e.taskPath(et.ID), 0770); err != nil {
		return err
	}

	log.Debugf("starting pod")

	dockerConfig, err := registry.GenDockerConfig(et.DockerRegistriesAuth, []string{et.Containers[0].Image})
	if err != nil {
		return err
	}

	podConfig := &driver.PodConfig{
		// generate a random pod id (don't use task id for future ability to restart
		// tasks failed to start and don't clash with existing pods)
		ID:            uuid.NewV4().String(),
		TaskID:        et.ID,
		Arch:          et.Arch,
		InitVolumeDir: toolboxContainerDir,
		DockerConfig:  dockerConfig,
		Containers:    make([]*driver.ContainerConfig, len(et.Containers)),
	}
	for i, c := range et.Containers {
		var cmd []string
		if i == 0 {
			cmd = []string{toolboxContainerPath, "sleeper"}
		}
		if c.Entrypoint != "" {
			cmd = strings.Split(c.Entrypoint, " ")
		}

		podConfig.Containers[i] = &driver.ContainerConfig{
			Image:      c.Image,
			Cmd:        cmd,
			Env:        c.Environment,
			User:       c.User,
			Privileged: c.Privileged,
		}
	}

	setupLogPath := e.setupLogPath(et.ID)
	if err := os.MkdirAll(filepath.Dir(setupLogPath), 0770); err != nil {
		return err
	}
	outf, err := os.Create(setupLogPath)
	if err != nil {
		return err
	}
	defer outf.Close()

	outf.WriteString("Starting pod.\n")
	pod, err := e.driver.NewPod(ctx, podConfig, outf)
	if err != nil {
		outf.WriteString(fmt.Sprintf("Pod failed to start. Error: %s\n", err))
		return err
	}
	outf.WriteString("Pod started.\n")

	if et.WorkingDir != "" {
		outf.WriteString(fmt.Sprintf("Creating working dir %q.\n", et.WorkingDir))
		if err := e.mkdir(ctx, et, pod, outf, et.WorkingDir); err != nil {
			outf.WriteString(fmt.Sprintf("Failed to create working dir %q. Error: %s\n", et.WorkingDir, err))
			return err
		}
	}

	rt.pod = pod
	return nil
}

func (e *Executor) executeTaskSteps(ctx context.Context, rt *runningTask, pod driver.Pod) (int, error) {
	for i, step := range rt.et.Steps {
		rt.Lock()
		rt.et.Status.Steps[i].Phase = types.ExecutorTaskPhaseRunning
		rt.et.Status.Steps[i].StartTime = util.TimePtr(time.Now())
		if err := e.sendExecutorTaskStatus(ctx, rt.et); err != nil {
			log.Errorf("err: %+v", err)
		}
		rt.Unlock()

		var err error
		var exitCode int
		var stepName string

		switch s := step.(type) {
		case *types.RunStep:
			log.Debugf("run step: %s", util.Dump(s))
			stepName = s.Name
			exitCode, err = e.doRunStep(ctx, s, rt.et, pod, e.stepLogPath(rt.et.ID, i))

		case *types.SaveToWorkspaceStep:
			log.Debugf("save to workspace step: %s", util.Dump(s))
			stepName = s.Name
			archivePath := e.archivePath(rt.et.ID, i)
			exitCode, err = e.doSaveToWorkspaceStep(ctx, s, rt.et, pod, e.stepLogPath(rt.et.ID, i), archivePath)

		case *types.RestoreWorkspaceStep:
			log.Debugf("restore workspace step: %s", util.Dump(s))
			stepName = s.Name
			exitCode, err = e.doRestoreWorkspaceStep(ctx, s, rt.et, pod, e.stepLogPath(rt.et.ID, i))

		case *types.SaveCacheStep:
			log.Debugf("save cache step: %s", util.Dump(s))
			stepName = s.Name
			archivePath := e.archivePath(rt.et.ID, i)
			exitCode, err = e.doSaveCacheStep(ctx, s, rt.et, pod, e.stepLogPath(rt.et.ID, i), archivePath)

		case *types.RestoreCacheStep:
			log.Debugf("restore cache step: %s", util.Dump(s))
			stepName = s.Name
			exitCode, err = e.doRestoreCacheStep(ctx, s, rt.et, pod, e.stepLogPath(rt.et.ID, i))

		default:
			return i, errors.Errorf("unknown step type: %s", util.Dump(s))
		}

		var serr error

		rt.Lock()
		rt.et.Status.Steps[i].EndTime = util.TimePtr(time.Now())

		rt.et.Status.Steps[i].Phase = types.ExecutorTaskPhaseSuccess

		if err != nil {
			if rt.et.Stop {
				rt.et.Status.Steps[i].Phase = types.ExecutorTaskPhaseStopped
			} else {
				rt.et.Status.Steps[i].Phase = types.ExecutorTaskPhaseFailed
			}
			serr = errors.Errorf("failed to execute step %s: %w", util.Dump(step), err)
		} else if exitCode != 0 {
			rt.et.Status.Steps[i].Phase = types.ExecutorTaskPhaseFailed
			rt.et.Status.Steps[i].ExitCode = exitCode
			serr = errors.Errorf("step %q failed with exitcode %d", stepName, exitCode)
		}

		if err := e.sendExecutorTaskStatus(ctx, rt.et); err != nil {
			log.Errorf("err: %+v", err)
		}
		rt.Unlock()

		if serr != nil {
			return i, serr
		}
	}

	return 0, nil
}

func (e *Executor) podsCleanerLoop(ctx context.Context) {
	for {
		log.Debugf("podsCleaner")

		if err := e.podsCleaner(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(1 * time.Second)
	}
}

func (e *Executor) podsCleaner(ctx context.Context) error {
	pods, err := e.getAllPods(ctx, true)
	if err != nil {
		return err
	}
	executors, err := e.driver.GetExecutors(ctx)
	if err != nil {
		return err
	}
	// always add ourself to executors
	executors = append(executors, e.id)

	for _, pod := range pods {
		taskID := pod.TaskID()
		// clean our owned pods
		if pod.ExecutorID() == e.id {
			if _, ok := e.runningTasks.get(taskID); !ok {
				log.Infof("removing pod %s for not running task: %s", pod.ID(), taskID)
				pod.Remove(ctx)
			}
		}

		// if no executor owns the pod we'll delete it
		owned := false
		for _, executorID := range executors {
			if pod.ExecutorID() == executorID {
				owned = true
				break
			}
		}
		if !owned {
			log.Infof("removing pod %s since it's not owned by any active executor", pod.ID())
			pod.Remove(ctx)
		}
	}

	return nil
}

func (e *Executor) executorStatusSenderLoop(ctx context.Context) {
	for {
		log.Debugf("executorStatusSender")

		if err := e.sendExecutorStatus(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(2 * time.Second)
	}
}

func (e *Executor) tasksUpdaterLoop(ctx context.Context) {
	for {
		log.Debugf("tasksUpdater")

		if err := e.tasksUpdater(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(2 * time.Second)
	}
}

// taskUpdater fetches the executor tasks from the scheduler and handles them
// this is useful to catch up when some tasks submissions from the scheduler to the executor
// APIs fails
func (e *Executor) tasksUpdater(ctx context.Context) error {
	ets, _, err := e.runserviceClient.GetExecutorTasks(ctx, e.id)
	if err != nil {
		log.Warnf("err: %v", err)
		return err
	}
	log.Debugf("ets: %v", util.Dump(ets))
	for _, et := range ets {
		go e.taskUpdater(ctx, et)
	}

	return nil
}

func (e *Executor) taskUpdater(ctx context.Context, et *types.ExecutorTask) {
	log.Debugf("et: %v", util.Dump(et))
	if et.Status.ExecutorID != e.id {
		return
	}

	if et.Stop {
		e.stopTask(ctx, et)
	}

	if et.Status.Phase == types.ExecutorTaskPhaseNotStarted {
		e.executeTask(ctx, et)
	}

	if et.Status.Phase == types.ExecutorTaskPhaseRunning {
		_, ok := e.runningTasks.get(et.ID)
		if !ok {
			log.Infof("marking executor task %s as failed since there's no running task", et.ID)
			et.Status.Phase = types.ExecutorTaskPhaseFailed
			// mark in progress step as failed too
			for _, s := range et.Status.Steps {
				if s.Phase == types.ExecutorTaskPhaseRunning {
					s.Phase = types.ExecutorTaskPhaseFailed
					s.EndTime = util.TimePtr(time.Now())
				}
			}
			e.sendExecutorTaskStatus(ctx, et)
		}
	}
}

func (e *Executor) tasksDataCleanerLoop(ctx context.Context) {
	for {
		log.Debugf("tasksDataCleaner")

		if err := e.tasksDataCleaner(ctx); err != nil {
			log.Errorf("err: %+v", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		time.Sleep(2 * time.Second)
	}
}

func (e *Executor) tasksDataCleaner(ctx context.Context) error {
	entries, err := ioutil.ReadDir(e.tasksDir())
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		etID := filepath.Base(entry.Name())

		_, resp, err := e.runserviceClient.GetExecutorTask(ctx, e.id, etID)
		if err != nil {
			if resp == nil {
				return err
			}
			if resp.StatusCode != http.StatusNotFound {
				return err
			}
		}
		if resp.StatusCode == http.StatusNotFound {
			taskDir := e.taskPath(etID)
			log.Infof("removing task dir %q", taskDir)
			// remove task dir
			if err := os.RemoveAll(taskDir); err != nil {
				return err
			}
		}
	}

	return nil
}

type runningTasks struct {
	tasks map[string]*runningTask
	m     sync.Mutex
}

type runningTask struct {
	sync.Mutex

	et  *types.ExecutorTask
	pod driver.Pod
}

func (r *runningTasks) get(rtID string) (*runningTask, bool) {
	r.m.Lock()
	defer r.m.Unlock()
	rt, ok := r.tasks[rtID]
	return rt, ok
}

func (r *runningTasks) addIfNotExists(rtID string, rt *runningTask) bool {
	r.m.Lock()
	defer r.m.Unlock()
	if _, ok := r.tasks[rtID]; ok {
		return false
	}
	r.tasks[rtID] = rt
	return true
}

func (r *runningTasks) add(rtID string, rt *runningTask) {
	r.m.Lock()
	defer r.m.Unlock()
	r.tasks[rtID] = rt
}

func (r *runningTasks) delete(rtID string) {
	r.m.Lock()
	defer r.m.Unlock()
	delete(r.tasks, rtID)
}

func (r *runningTasks) len() int {
	r.m.Lock()
	defer r.m.Unlock()
	return len(r.tasks)
}

func (e *Executor) handleTasks(ctx context.Context, c <-chan *types.ExecutorTask) {
	for et := range c {
		go e.executeTask(ctx, et)
	}
}

func (e *Executor) getExecutorID() (string, error) {
	id, err := ioutil.ReadFile(e.executorIDPath())
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return string(id), nil
}

func (e *Executor) saveExecutorID(id string) error {
	if err := common.WriteFileAtomic(e.executorIDPath(), []byte(id), 0660); err != nil {
		return errors.Errorf("failed to write executor id file: %w", err)
	}
	return nil
}

type Executor struct {
	c                *config.Executor
	runserviceClient *rsapi.Client
	id               string
	runningTasks     *runningTasks
	driver           driver.Driver
	listenURL        string
	dynamic          bool
}

func NewExecutor(c *config.Executor) (*Executor, error) {
	if c.Debug {
		level.SetLevel(zapcore.DebugLevel)
	}

	var err error
	c.ToolboxPath, err = filepath.Abs(c.ToolboxPath)
	if err != nil {
		return nil, errors.Errorf("cannot determine \"agola-toolbox\" absolute path: %w", err)
	}

	e := &Executor{
		c:                c,
		runserviceClient: rsapi.NewClient(c.RunserviceURL),
		runningTasks: &runningTasks{
			tasks: make(map[string]*runningTask),
		},
	}

	if err := os.MkdirAll(e.tasksDir(), 0770); err != nil {
		return nil, err
	}

	id, err := e.getExecutorID()
	if err != nil {
		return nil, err
	}
	if id == "" {
		id = uuid.NewV4().String()
		if err := e.saveExecutorID(id); err != nil {
			return nil, err
		}
	}

	e.id = id

	addr, err := sockaddr.GetPrivateIP()
	if err != nil {
		return nil, errors.Errorf("cannot discover executor listen address: %w", err)
	}
	if addr == "" {
		return nil, errors.Errorf("cannot discover executor listen address")
	}
	u := url.URL{Scheme: "http"}
	if c.Web.TLS {
		u.Scheme = "https"
	}
	_, port, err := net.SplitHostPort(c.Web.ListenAddress)
	if err != nil {
		return nil, errors.Errorf("cannot get web listen port: %w", err)
	}
	u.Host = net.JoinHostPort(addr, port)
	e.listenURL = u.String()

	var d driver.Driver
	switch c.Driver.Type {
	case config.DriverTypeDocker:
		d, err = driver.NewDockerDriver(logger, e.id, "/tmp/agola/bin", e.c.ToolboxPath)
		if err != nil {
			return nil, errors.Errorf("failed to create docker driver: %w", err)
		}
	case config.DriverTypeK8s:
		d, err = driver.NewK8sDriver(logger, e.id, c.ToolboxPath)
		if err != nil {
			return nil, errors.Errorf("failed to create kubernetes driver: %w", err)
		}
		e.dynamic = true
	default:
		return nil, errors.Errorf("unknown driver type %q", c.Driver.Type)
	}
	e.driver = d

	return e, nil
}

func (e *Executor) Run(ctx context.Context) error {
	if err := e.driver.Setup(ctx); err != nil {
		return err
	}

	ch := make(chan *types.ExecutorTask)
	schedulerHandler := NewTaskSubmissionHandler(ch)
	logsHandler := NewLogsHandler(logger, e)
	archivesHandler := NewArchivesHandler(e)

	router := mux.NewRouter()
	apirouter := router.PathPrefix("/api/v1alpha").Subrouter()

	apirouter.Handle("/executor", schedulerHandler).Methods("POST")
	apirouter.Handle("/executor/logs", logsHandler).Methods("GET")
	apirouter.Handle("/executor/archives", archivesHandler).Methods("GET")

	go e.executorStatusSenderLoop(ctx)
	go e.podsCleanerLoop(ctx)
	go e.tasksUpdaterLoop(ctx)
	go e.tasksDataCleanerLoop(ctx)

	go e.handleTasks(ctx, ch)

	httpServer := http.Server{
		Addr:    e.c.Web.ListenAddress,
		Handler: apirouter,
	}
	lerrCh := make(chan error)
	go func() {
		lerrCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		log.Infof("runservice executor exiting")
		httpServer.Close()
		return nil
	case err := <-lerrCh:
		log.Errorf("http server listen error: %v", err)
		return err
	}
}
