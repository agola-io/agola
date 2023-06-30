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

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
	sockaddr "github.com/hashicorp/go-sockaddr"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sorintlab/errors"

	"agola.io/agola/internal/common"
	"agola.io/agola/internal/services/config"
	"agola.io/agola/internal/services/executor/driver"
	"agola.io/agola/internal/services/executor/registry"
	"agola.io/agola/internal/services/handlers"
	"agola.io/agola/internal/util"
	rsapitypes "agola.io/agola/services/runservice/api/types"
	rsclient "agola.io/agola/services/runservice/client"
	"agola.io/agola/services/runservice/types"
)

const (
	defaultShell = "/bin/sh -e"

	toolboxContainerDir = "/mnt/agola"

	// podCreationTimeout is the maximum time to wait for pod creation.
	podCreationTimeout = time.Minute * 5

	// tasksTimeoutCleanerInterval is the maximum time to wait for tasks timeout cleaner
	tasksTimeoutCleanerInterval = time.Second * 2
)

var (
	toolboxContainerPath = filepath.Join(toolboxContainerDir, "/agola-toolbox")
)

func (e *Executor) getAllPods(ctx context.Context, all bool) ([]driver.Pod, error) {
	pods, err := e.driver.GetPods(ctx, all)
	return pods, errors.WithStack(err)
}

func stepUser(et *rsapitypes.ExecutorTask) string {
	// use the container specified user and override with task user if defined
	user := et.Spec.Containers[0].User
	if et.Spec.User != "" {
		user = et.Spec.User
	}

	return user
}

func (e *Executor) createFile(ctx context.Context, pod driver.Pod, command, user string, outf io.Writer) (string, error) {
	cmd := []string{toolboxContainerPath, "createfile"}

	var buf bytes.Buffer
	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		User:        user,
		AttachStdin: true,
		Stdout:      &buf,
		Stderr:      outf,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return "", errors.WithStack(err)
	}

	stdin := ce.Stdin()
	go func() {
		_, _ = io.WriteString(stdin, command+"\n")
		stdin.Close()
	}()

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return "", errors.WithStack(err)
	}
	if exitCode != 0 {
		return "", errors.Errorf("toolbox exited with code: %d", exitCode)
	}

	return buf.String(), nil
}

func (e *Executor) doRunStep(ctx context.Context, s *types.RunStep, et *rsapitypes.ExecutorTask, pod driver.Pod, logPath string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0770); err != nil {
		return -1, errors.WithStack(err)
	}
	outf, err := os.Create(logPath)
	if err != nil {
		return -1, errors.WithStack(err)
	}
	defer outf.Close()

	// TODO(sgotti) this line is used only for old runconfig versions that don't
	// set a task default shell in the runconfig
	shell := defaultShell
	if et.Spec.Shell != "" {
		shell = et.Spec.Shell
	}
	if s.Shell != "" {
		shell = s.Shell
	}

	var cmd []string
	if s.Command != "" {
		filename, err := e.createFile(ctx, pod, s.Command, stepUser(et), outf)
		if err != nil {
			return -1, errors.Wrapf(err, "create file err")
		}

		args := strings.Split(shell, " ")
		cmd = append(args, filename)
	} else {
		cmd = strings.Split(shell, " ")
	}

	// override task working dir with runstep working dir if provided
	workingDir := et.Spec.WorkingDir
	if s.WorkingDir != "" {
		workingDir = s.WorkingDir
	}

	// generate the environment using the task environment and then overriding with the runstep environment
	environment := map[string]string{}
	for envName, envValue := range et.Spec.Environment {
		environment[envName] = envValue
	}
	for envName, envValue := range s.Environment {
		environment[envName] = envValue
	}

	workingDir, err = e.expandDir(ctx, et, pod, outf, workingDir)
	if err != nil {
		_, _ = outf.WriteString(fmt.Sprintf("failed to expand working dir %q. Error: %s\n", workingDir, err))
		return -1, errors.WithStack(err)
	}

	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		Env:         environment,
		WorkingDir:  workingDir,
		User:        stepUser(et),
		AttachStdin: true,
		Stdout:      outf,
		Stderr:      outf,
		Tty:         *s.Tty,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return -1, errors.WithStack(err)
	}

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return -1, errors.WithStack(err)
	}

	return exitCode, nil
}

func (e *Executor) doSaveToWorkspaceStep(ctx context.Context, s *types.SaveToWorkspaceStep, et *rsapitypes.ExecutorTask, pod driver.Pod, logPath string, archivePath string) (int, error) {
	cmd := []string{toolboxContainerPath, "archive"}

	if err := os.MkdirAll(filepath.Dir(logPath), 0770); err != nil {
		return -1, errors.WithStack(err)
	}
	logf, err := os.Create(logPath)
	if err != nil {
		return -1, errors.WithStack(err)
	}
	defer logf.Close()

	if err := os.MkdirAll(filepath.Dir(archivePath), 0770); err != nil {
		return -1, errors.WithStack(err)
	}
	archivef, err := os.Create(archivePath)
	if err != nil {
		return -1, errors.WithStack(err)
	}
	defer archivef.Close()

	workingDir, err := e.expandDir(ctx, et, pod, logf, et.Spec.WorkingDir)
	if err != nil {
		_, _ = logf.WriteString(fmt.Sprintf("failed to expand working dir %q. Error: %s\n", et.Spec.WorkingDir, err))
		return -1, errors.WithStack(err)
	}

	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		Env:         et.Spec.Environment,
		WorkingDir:  workingDir,
		User:        stepUser(et),
		AttachStdin: true,
		Stdout:      archivef,
		Stderr:      logf,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return -1, errors.WithStack(err)
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
		_ = enc.Encode(a)
		stdin.Close()
	}()

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return -1, errors.WithStack(err)
	}

	return exitCode, nil
}

func (e *Executor) expandDir(ctx context.Context, et *rsapitypes.ExecutorTask, pod driver.Pod, logf io.Writer, dir string) (string, error) {
	args := []string{dir}
	cmd := append([]string{toolboxContainerPath, "expanddir"}, args...)

	// limit the template answer to max 1MiB
	stdout := &bytes.Buffer{}

	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		Env:         et.Spec.Environment,
		User:        stepUser(et),
		AttachStdin: true,
		Stdout:      stdout,
		Stderr:      logf,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return "", errors.WithStack(err)
	}

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return "", errors.WithStack(err)
	}
	if exitCode != 0 {
		return "", errors.Errorf("expanddir ended with exit code %d", exitCode)
	}

	return stdout.String(), nil
}

func (e *Executor) mkdir(ctx context.Context, et *rsapitypes.ExecutorTask, pod driver.Pod, logf io.Writer, dir string) error {
	args := []string{dir}
	cmd := append([]string{toolboxContainerPath, "mkdir"}, args...)

	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		Env:         et.Spec.Environment,
		User:        stepUser(et),
		AttachStdin: true,
		Stdout:      logf,
		Stderr:      logf,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return errors.WithStack(err)
	}

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return errors.WithStack(err)
	}
	if exitCode != 0 {
		return errors.Errorf("mkdir ended with exit code %d", exitCode)
	}

	return nil
}

func (e *Executor) template(ctx context.Context, et *rsapitypes.ExecutorTask, pod driver.Pod, logf io.Writer, key string) (string, error) {
	cmd := []string{toolboxContainerPath, "template"}

	// limit the template answer to max 1MiB
	stdout := util.NewLimitedBuffer(1024 * 1024)

	workingDir, err := e.expandDir(ctx, et, pod, logf, et.Spec.WorkingDir)
	if err != nil {
		_, _ = io.WriteString(logf, fmt.Sprintf("failed to expand working dir %q. Error: %s\n", et.Spec.WorkingDir, err))
		return "", errors.WithStack(err)
	}

	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		Env:         et.Spec.Environment,
		WorkingDir:  workingDir,
		User:        stepUser(et),
		AttachStdin: true,
		Stdout:      stdout,
		Stderr:      logf,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return "", errors.WithStack(err)
	}

	stdin := ce.Stdin()
	go func() {
		_, _ = io.WriteString(stdin, key)
		stdin.Close()
	}()

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return "", errors.WithStack(err)
	}
	if exitCode != 0 {
		return "", errors.Errorf("template ended with exit code %d", exitCode)
	}

	return stdout.String(), nil
}

func (e *Executor) unarchive(ctx context.Context, et *rsapitypes.ExecutorTask, source io.Reader, pod driver.Pod, logf io.Writer, destDir string, overwrite, removeDestDir bool) error {
	args := []string{"--destdir", destDir}
	if overwrite {
		args = append(args, "--overwrite")
	}
	if removeDestDir {
		args = append(args, "--remove-destdir")
	}
	cmd := append([]string{toolboxContainerPath, "unarchive"}, args...)

	workingDir, err := e.expandDir(ctx, et, pod, logf, et.Spec.WorkingDir)
	if err != nil {
		_, _ = io.WriteString(logf, fmt.Sprintf("failed to expand working dir %q. Error: %s\n", et.Spec.WorkingDir, err))
		return errors.WithStack(err)
	}

	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		Env:         et.Spec.Environment,
		WorkingDir:  workingDir,
		User:        stepUser(et),
		AttachStdin: true,
		Stdout:      logf,
		Stderr:      logf,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return errors.WithStack(err)
	}

	stdin := ce.Stdin()
	go func() {
		_, _ = io.Copy(stdin, source)
		stdin.Close()
	}()

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return errors.WithStack(err)
	}
	if exitCode != 0 {
		return errors.Errorf("unarchive ended with exit code %d", exitCode)
	}

	return nil
}

func (e *Executor) doRestoreWorkspaceStep(ctx context.Context, s *types.RestoreWorkspaceStep, et *rsapitypes.ExecutorTask, pod driver.Pod, logPath string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0770); err != nil {
		return -1, errors.WithStack(err)
	}
	logf, err := os.Create(logPath)
	if err != nil {
		return -1, errors.WithStack(err)
	}
	defer logf.Close()

	for _, op := range et.Spec.WorkspaceOperations {
		e.log.Debug().Msgf("unarchiving workspace for taskID: %s, step: %d", op.TaskID, op.Step)
		resp, err := e.runserviceClient.GetArchive(ctx, op.TaskID, op.Step)
		if err != nil {
			// TODO(sgotti) retry before giving up
			fmt.Fprintf(logf, "error reading workspace archive: %v\n", err)
			return -1, errors.WithStack(err)
		}
		archivef := resp.Body
		if err := e.unarchive(ctx, et, archivef, pod, logf, s.DestDir, false, false); err != nil {
			archivef.Close()
			return -1, errors.WithStack(err)
		}
		archivef.Close()
	}

	return 0, nil
}

func (e *Executor) doSaveCacheStep(ctx context.Context, s *types.SaveCacheStep, et *rsapitypes.ExecutorTask, pod driver.Pod, logPath string, archivePath string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0770); err != nil {
		return -1, errors.WithStack(err)
	}
	logf, err := os.Create(logPath)
	if err != nil {
		return -1, errors.WithStack(err)
	}
	defer logf.Close()

	save := false

	// calculate key from template
	cacheKey, err := e.template(ctx, et, pod, logf, s.Key)
	if err != nil {
		return -1, errors.WithStack(err)
	}
	fmt.Fprintf(logf, "cache key %q\n", cacheKey)

	// append cache prefix
	fullCacheKey := et.Spec.CachePrefix + "-" + cacheKey

	// check that the cache key doesn't already exists
	resp, err := e.runserviceClient.CheckCache(ctx, fullCacheKey, false)
	if err != nil {
		// ignore 404 errors since they means that the cache key doesn't exists
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			fmt.Fprintf(logf, "no cache available for key %q. Saving.\n", cacheKey)
			save = true
		} else {
			// TODO(sgotti) retry before giving up
			fmt.Fprintf(logf, "error checking for cache key %q: %v\n", cacheKey, err)
			return -1, errors.WithStack(err)
		}
	}
	if !save {
		fmt.Fprintf(logf, "cache for key %q already exists\n", cacheKey)
		return 0, nil
	}

	fmt.Fprintf(logf, "archiving cache with key %q\n", cacheKey)
	exitCode, err := e.archiveCache(ctx, s, et, pod, logf, archivePath)
	if err != nil {
		return exitCode, err
	}

	if err := e.SendCache(ctx, fullCacheKey, archivePath); err != nil {
		return exitCode, errors.WithStack(err)
	}

	return exitCode, nil
}

func (e *Executor) archiveCache(ctx context.Context, s *types.SaveCacheStep, et *rsapitypes.ExecutorTask, pod driver.Pod, logf io.Writer, archivePath string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(archivePath), 0770); err != nil {
		return -1, errors.WithStack(err)
	}
	archivef, err := os.Create(archivePath)
	if err != nil {
		return -1, errors.WithStack(err)
	}
	defer archivef.Close()

	workingDir, err := e.expandDir(ctx, et, pod, logf, et.Spec.WorkingDir)
	if err != nil {
		_, _ = io.WriteString(logf, fmt.Sprintf("failed to expand working dir %q. Error: %s\n", et.Spec.WorkingDir, err))
		return -1, errors.WithStack(err)
	}

	cmd := []string{toolboxContainerPath, "archive"}

	execConfig := &driver.ExecConfig{
		Cmd:         cmd,
		Env:         et.Spec.Environment,
		WorkingDir:  workingDir,
		User:        stepUser(et),
		AttachStdin: true,
		Stdout:      archivef,
		Stderr:      logf,
	}

	ce, err := pod.Exec(ctx, execConfig)
	if err != nil {
		return -1, errors.WithStack(err)
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
		_ = enc.Encode(a)
		stdin.Close()
	}()

	exitCode, err := ce.Wait(ctx)
	if err != nil {
		return -1, errors.WithStack(err)
	}

	if exitCode != 0 {
		return exitCode, errors.Errorf("save cache archiving command ended with exit code %d", exitCode)
	}

	return exitCode, nil
}

func (e *Executor) SendCache(ctx context.Context, fullCacheKey, cacheArchivePath string) error {
	f, err := os.Open(cacheArchivePath)
	if err != nil {
		return errors.WithStack(err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return errors.WithStack(err)
	}

	// send cache archive to scheduler
	if resp, err := e.runserviceClient.PutCache(ctx, fullCacheKey, fi.Size(), f); err != nil {
		if resp == nil || (resp != nil && resp.StatusCode != http.StatusNotModified) {
			return errors.WithStack(err)
		}
	}

	return nil
}

func (e *Executor) doRestoreCacheStep(ctx context.Context, s *types.RestoreCacheStep, et *rsapitypes.ExecutorTask, pod driver.Pod, logPath string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0770); err != nil {
		return -1, errors.WithStack(err)
	}
	logf, err := os.Create(logPath)
	if err != nil {
		return -1, errors.WithStack(err)
	}
	defer logf.Close()

	fmt.Fprintf(logf, "restoring cache: %s\n", util.Dump(s))
	for _, cacheKeyTemplate := range s.Keys {
		// calculate key from template
		cacheKey, err := e.template(ctx, et, pod, logf, cacheKeyTemplate)
		if err != nil {
			return -1, errors.WithStack(err)
		}
		fmt.Fprintf(logf, "cache key %q\n", cacheKey)

		// append cache prefix
		fullCacheKey := et.Spec.CachePrefix + "-" + cacheKey

		resp, err := e.runserviceClient.GetCache(ctx, fullCacheKey, true)
		if err != nil {
			// ignore 404 errors since they means that the cache key doesn't exists
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				fmt.Fprintf(logf, "no cache available for key %q\n", cacheKey)
				continue
			}
			// TODO(sgotti) retry before giving up
			fmt.Fprintf(logf, "error reading cache: %v\n", err)
			return -1, errors.WithStack(err)
		}
		fmt.Fprintf(logf, "restoring cache with key %q\n", cacheKey)
		cachef := resp.Body
		if err := e.unarchive(ctx, et, cachef, pod, logf, s.DestDir, false, false); err != nil {
			cachef.Close()
			return -1, errors.WithStack(err)
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
		return errors.WithStack(err)
	}

	executorGroup, err := e.driver.ExecutorGroup(ctx)
	if err != nil {
		return errors.WithStack(err)
	}
	// report all the executors that are active OR that have some owned pods not yet removed
	activeExecutors, err := e.driver.GetExecutors(ctx)
	if err != nil {
		return errors.WithStack(err)
	}
	pods, err := e.driver.GetPods(ctx, true)
	if err != nil {
		return errors.WithStack(err)
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

	executor := &rsapitypes.ExecutorStatus{
		Archs:                     archs,
		AllowPrivilegedContainers: e.c.AllowPrivilegedContainers,
		ListenURL:                 e.listenURL,
		Labels:                    labels,
		ActiveTasksLimit:          e.c.ActiveTasksLimit,
		ActiveTasks:               activeTasks,
		Dynamic:                   e.dynamic,
		ExecutorGroup:             executorGroup,
		SiblingsExecutors:         siblingsExecutors,
	}

	e.log.Debug().Msgf("send executor status: %s", util.Dump(executor))
	_, err = e.runserviceClient.SendExecutorStatus(ctx, e.id, executor)
	return errors.WithStack(err)
}

func (e *Executor) sendExecutorTaskStatus(ctx context.Context, et *rsapitypes.ExecutorTask) error {
	e.log.Debug().Msgf("send executor task: %s. status: %s", et.ID, et.Status.Phase)

	_, err := e.runserviceClient.SendExecutorTaskStatus(ctx, e.id, et.ID, et.Status)
	return errors.WithStack(err)
}

func (e *Executor) executeTask(rt *runningTask) {
	// * save in local state that we have a running task
	// * start the pod
	// * then update the executortask status to in-progress
	// if something fails pod will be cleaned up by the pod cleaner goroutine
	// In this way we are sure that the pod cleaner will only remove pod that don't
	// have an in progress running task

	rt.Lock()
	ctx := rt.ctx

	// wait for context to be done and then stop the pod if running
	go func() {
		<-ctx.Done()
		if rt.pod != nil {
			if err := rt.pod.Stop(context.Background()); err != nil {
				log.Err(err).Msgf("error stopping the pod: %+v", err)
			}
		}
	}()

	defer func() {
		rt.Lock()
		rt.cancel()
		rt.Unlock()
	}()

	et := rt.et

	et.Status.Phase = types.ExecutorTaskPhaseRunning
	et.Status.StartTime = util.TimeP(time.Now())
	et.Status.SetupStep.Phase = types.ExecutorTaskPhaseRunning
	et.Status.SetupStep.StartTime = util.TimeP(time.Now())
	if err := e.sendExecutorTaskStatus(ctx, et); err != nil {
		e.log.Err(err).Send()
	}

	rt.Unlock()
	if err := e.setupTask(ctx, rt); err != nil {
		rt.Lock()
		e.log.Err(err).Send()
		et.Status.Phase = types.ExecutorTaskPhaseFailed
		et.Status.EndTime = util.TimeP(time.Now())
		et.Status.SetupStep.Phase = types.ExecutorTaskPhaseFailed
		et.Status.SetupStep.EndTime = util.TimeP(time.Now())
		if err := e.sendExecutorTaskStatus(ctx, et); err != nil {
			e.log.Err(err).Send()
		}
		rt.Unlock()
		return
	}

	rt.Lock()
	rt.podStartTime = util.TimeP(time.Now())
	et.Status.SetupStep.Phase = types.ExecutorTaskPhaseSuccess
	et.Status.SetupStep.EndTime = util.TimeP(time.Now())
	if err := e.sendExecutorTaskStatus(ctx, et); err != nil {
		e.log.Err(err).Send()
	}

	rt.Unlock()

	_, err := e.executeTaskSteps(ctx, rt, rt.pod)

	rt.Lock()
	if err != nil {
		e.log.Err(err).Send()
		if rt.timedout {
			et.Status.Phase = types.ExecutorTaskPhaseFailed
			et.Status.Timedout = true
		} else if rt.et.Stop {
			et.Status.Phase = types.ExecutorTaskPhaseStopped
		} else {
			et.Status.Phase = types.ExecutorTaskPhaseFailed
		}
	} else {
		et.Status.Phase = types.ExecutorTaskPhaseSuccess
	}

	et.Status.EndTime = util.TimeP(time.Now())

	if err := e.sendExecutorTaskStatus(ctx, et); err != nil {
		e.log.Err(err).Send()
	}
	rt.Unlock()
}

func (e *Executor) setupTask(ctx context.Context, rt *runningTask) error {
	et := rt.et
	if err := os.RemoveAll(e.taskPath(et.ID)); err != nil {
		return errors.WithStack(err)
	}
	if err := os.MkdirAll(e.taskPath(et.ID), 0770); err != nil {
		return errors.WithStack(err)
	}

	setupLogPath := e.setupLogPath(et.ID)
	if err := os.MkdirAll(filepath.Dir(setupLogPath), 0770); err != nil {
		return errors.WithStack(err)
	}
	outf, err := os.Create(setupLogPath)
	if err != nil {
		return errors.WithStack(err)
	}
	defer outf.Close()

	// error out if privileged containers are required but not allowed
	requiresPrivilegedContainers := false
	for _, c := range et.Spec.Containers {
		if c.Privileged {
			requiresPrivilegedContainers = true
			break
		}
	}
	if requiresPrivilegedContainers && !e.c.AllowPrivilegedContainers {
		_, _ = outf.WriteString("Executor doesn't allow executing privileged containers.\n")
		return errors.Errorf("executor doesn't allow executing privileged containers")
	}

	e.log.Debug().Msgf("starting pod")

	dockerRegistriesAuth := map[string]registry.DockerRegistryAuth{}
	for n, v := range et.Spec.DockerRegistriesAuth {
		dockerRegistriesAuth[n] = registry.DockerRegistryAuth{
			Type:     registry.DockerRegistryAuthType(v.Type),
			Username: v.Username,
			Password: v.Password,
			Auth:     v.Auth,
		}
	}

	dockerConfig, err := registry.GenDockerConfig(dockerRegistriesAuth, []string{et.Spec.Containers[0].Image})
	if err != nil {
		return errors.WithStack(err)
	}

	podConfig := &driver.PodConfig{
		// generate a random pod id (don't use task id for future ability to restart
		// tasks failed to start and don't clash with existing pods)
		ID:            uuid.Must(uuid.NewV4()).String(),
		TaskID:        et.ID,
		Arch:          et.Spec.Arch,
		InitVolumeDir: toolboxContainerDir,
		DockerConfig:  dockerConfig,
		Containers:    make([]*driver.ContainerConfig, len(et.Spec.Containers)),
	}
	for i, c := range et.Spec.Containers {
		var cmd []string
		if i == 0 {
			cmd = []string{toolboxContainerPath, "sleeper"}
		}
		if c.Entrypoint != "" {
			cmd = strings.Split(c.Entrypoint, " ")
		}

		containerConfig := &driver.ContainerConfig{
			Image:      c.Image,
			Cmd:        cmd,
			Env:        c.Environment,
			User:       c.User,
			Privileged: c.Privileged,
			Volumes:    make([]driver.Volume, len(c.Volumes)),
		}

		for vIndex, cVol := range c.Volumes {
			containerConfig.Volumes[vIndex] = driver.Volume{
				Path: cVol.Path,
			}
			if cVol.TmpFS != nil {
				containerConfig.Volumes[vIndex].TmpFS = &driver.VolumeTmpFS{
					Size: cVol.TmpFS.Size,
				}
			}
		}

		podConfig.Containers[i] = containerConfig
	}

	_, _ = outf.WriteString("Starting pod.\n")
	podCtx, cancel := context.WithTimeout(ctx, podCreationTimeout)
	defer cancel()
	pod, err := e.driver.NewPod(podCtx, podConfig, outf)
	if err != nil {
		_, _ = outf.WriteString(fmt.Sprintf("Pod failed to start. Error: %s\n", err))
		return errors.WithStack(err)
	}
	_, _ = outf.WriteString("Pod started.\n")

	if et.Spec.WorkingDir != "" {
		_, _ = outf.WriteString(fmt.Sprintf("Creating working dir %q.\n", et.Spec.WorkingDir))
		if err := e.mkdir(ctx, et, pod, outf, et.Spec.WorkingDir); err != nil {
			_, _ = outf.WriteString(fmt.Sprintf("Failed to create working dir %q. Error: %s\n", et.Spec.WorkingDir, err))
			return errors.WithStack(err)
		}
	}

	rt.pod = pod
	return nil
}

func (e *Executor) executeTaskSteps(ctx context.Context, rt *runningTask, pod driver.Pod) (int, error) {
	for i, step := range rt.et.Spec.Steps {
		rt.Lock()
		rt.et.Status.Steps[i].Phase = types.ExecutorTaskPhaseRunning
		rt.et.Status.Steps[i].StartTime = util.TimeP(time.Now())
		if err := e.sendExecutorTaskStatus(ctx, rt.et); err != nil {
			e.log.Err(err).Send()
		}
		rt.Unlock()

		var err error
		var exitCode int
		var stepName string

		switch s := step.(type) {
		case *types.RunStep:
			e.log.Debug().Msgf("run step: %s", util.Dump(s))
			stepName = s.Name
			exitCode, err = e.doRunStep(ctx, s, rt.et, pod, e.stepLogPath(rt.et.ID, i))

		case *types.SaveToWorkspaceStep:
			e.log.Debug().Msgf("save to workspace step: %s", util.Dump(s))
			stepName = s.Name
			archivePath := e.archivePath(rt.et.ID, i)
			exitCode, err = e.doSaveToWorkspaceStep(ctx, s, rt.et, pod, e.stepLogPath(rt.et.ID, i), archivePath)

		case *types.RestoreWorkspaceStep:
			e.log.Debug().Msgf("restore workspace step: %s", util.Dump(s))
			stepName = s.Name
			exitCode, err = e.doRestoreWorkspaceStep(ctx, s, rt.et, pod, e.stepLogPath(rt.et.ID, i))

		case *types.SaveCacheStep:
			e.log.Debug().Msgf("save cache step: %s", util.Dump(s))
			stepName = s.Name
			archivePath := e.archivePath(rt.et.ID, i)
			exitCode, err = e.doSaveCacheStep(ctx, s, rt.et, pod, e.stepLogPath(rt.et.ID, i), archivePath)

		case *types.RestoreCacheStep:
			e.log.Debug().Msgf("restore cache step: %s", util.Dump(s))
			stepName = s.Name
			exitCode, err = e.doRestoreCacheStep(ctx, s, rt.et, pod, e.stepLogPath(rt.et.ID, i))

		default:
			return i, errors.Errorf("unknown step type: %s", util.Dump(s))
		}

		var serr error

		rt.Lock()
		rt.et.Status.Steps[i].EndTime = util.TimeP(time.Now())

		rt.et.Status.Steps[i].Phase = types.ExecutorTaskPhaseSuccess

		if err != nil {
			if rt.et.Stop {
				rt.et.Status.Steps[i].Phase = types.ExecutorTaskPhaseStopped
			} else {
				rt.et.Status.Steps[i].Phase = types.ExecutorTaskPhaseFailed
			}
			serr = errors.Wrapf(err, "failed to execute step %s", util.Dump(step))
		} else if exitCode != 0 {
			if rt.et.Stop {
				rt.et.Status.Steps[i].Phase = types.ExecutorTaskPhaseStopped
			} else {
				rt.et.Status.Steps[i].Phase = types.ExecutorTaskPhaseFailed
			}
			rt.et.Status.Steps[i].ExitStatus = util.IntP(exitCode)
			serr = errors.Errorf("step %q failed with exitcode %d", stepName, exitCode)
		} else if exitCode == 0 {
			rt.et.Status.Steps[i].ExitStatus = util.IntP(exitCode)
		}

		if err := e.sendExecutorTaskStatus(ctx, rt.et); err != nil {
			e.log.Err(err).Send()
		}
		rt.Unlock()

		if serr != nil {
			return i, errors.WithStack(serr)
		}
	}

	return 0, nil
}

func (e *Executor) podsCleanerLoop(ctx context.Context) {
	for {
		e.log.Debug().Msgf("podsCleaner")

		if err := e.podsCleaner(ctx); err != nil {
			e.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(1 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (e *Executor) podsCleaner(ctx context.Context) error {
	pods, err := e.getAllPods(ctx, true)
	if err != nil {
		return errors.WithStack(err)
	}
	executors, err := e.driver.GetExecutors(ctx)
	if err != nil {
		return errors.WithStack(err)
	}
	// always add ourself to executors
	executors = append(executors, e.id)

	for _, pod := range pods {
		taskID := pod.TaskID()
		// clean our owned pods
		if pod.ExecutorID() == e.id {
			if _, ok := e.runningTasks.get(taskID); !ok {
				e.log.Info().Msgf("removing pod %s for not running task: %s", pod.ID(), taskID)
				_ = pod.Remove(ctx)
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
			e.log.Info().Msgf("removing pod %s since it's not owned by any active executor", pod.ID())
			_ = pod.Remove(ctx)
		}
	}

	return nil
}

func (e *Executor) executorStatusSenderLoop(ctx context.Context) {
	for {
		e.log.Debug().Msgf("executorStatusSenderLoop")

		if err := e.sendExecutorStatus(ctx); err != nil {
			e.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(2 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (e *Executor) executorTasksStatusSenderLoop(ctx context.Context) {
	for {
		e.log.Debug().Msgf("executorTasksStatusSenderLoop")

		for _, rtID := range e.runningTasks.ids() {
			rt, ok := e.runningTasks.get(rtID)
			if !ok {
				continue
			}

			rt.Lock()
			if err := e.sendExecutorTaskStatus(ctx, rt.et); err != nil {
				e.log.Err(err).Send()
				rt.Unlock()
				continue
			}

			// remove running task if send was successful and it's not executing
			select {
			case <-ctx.Done():
				e.runningTasks.delete(rtID)
			default:
			}

			rt.Unlock()
		}

		sleepCh := time.NewTimer(2 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (e *Executor) tasksUpdaterLoop(ctx context.Context) {
	for {
		e.log.Debug().Msgf("tasksUpdater")

		if err := e.tasksUpdater(ctx); err != nil {
			e.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(2 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

// taskUpdater fetches the executor tasks from the scheduler and handles them
// this is useful to catch up when some tasks submissions from the scheduler to the executor
// APIs fails
func (e *Executor) tasksUpdater(ctx context.Context) error {
	e.tasksUpdaterMutex.Lock()
	defer e.tasksUpdaterMutex.Unlock()

	ets, _, err := e.runserviceClient.GetExecutorTasks(ctx, e.id)
	if err != nil {
		e.log.Warn().Err(err).Send()
		return errors.WithStack(err)
	}
	e.log.Debug().Msgf("ets: %s", util.Dump(ets))
	for _, et := range ets {
		e.taskUpdater(ctx, et)
	}

	// stop and remove runningTasks not existing in the runservice
	etIDsMap := map[string]struct{}{}
	for _, et := range ets {
		etIDsMap[et.ID] = struct{}{}
	}

	for _, rtID := range e.runningTasks.ids() {
		if _, ok := etIDsMap[rtID]; ok {
			continue
		}
		if rt, ok := e.runningTasks.get(rtID); ok {
			rt.cancel()
			e.runningTasks.delete(rtID)
		}
	}

	return nil
}

func (e *Executor) taskUpdater(ctx context.Context, et *rsapitypes.ExecutorTask) {
	e.log.Debug().Msgf("et: %s", util.Dump(et))
	if et.ExecutorID != e.id {
		return
	}

	rt, _ := e.runningTasks.get(et.ID)
	if rt != nil {
		rt.Lock()
		// update running task Stop value only when there's a transitions from false to true,
		// other spec values cannot change once the task has been scheduled
		if !rt.et.Stop && et.Stop {
			rt.et.Stop = et.Stop

			// cancel the running task
			rt.cancel()
		}
		rt.Unlock()

		return
	}

	// rt == nil

	// only send cancelled phase when the executor task isn't in running tasks and is not started
	if et.Stop && et.Status.Phase == types.ExecutorTaskPhaseNotStarted {
		et.Status.Phase = types.ExecutorTaskPhaseCancelled
		go func() {
			if err := e.sendExecutorTaskStatus(ctx, et); err != nil {
				e.log.Err(err).Send()
			}
		}()
	}

	if et.Status.Phase == types.ExecutorTaskPhaseRunning {
		e.log.Info().Msgf("marking executor task %s as failed since there's no running task", et.ID)
		et.Status.Phase = types.ExecutorTaskPhaseFailed
		et.Status.EndTime = util.TimeP(time.Now())
		// mark in progress step as failed too
		for _, s := range et.Status.Steps {
			if s.Phase == types.ExecutorTaskPhaseRunning {
				s.Phase = types.ExecutorTaskPhaseFailed
				s.EndTime = util.TimeP(time.Now())
			}
		}
		go func() {
			if err := e.sendExecutorTaskStatus(ctx, et); err != nil {
				e.log.Err(err).Send()
			}
		}()
	}

	if !et.Stop && et.Status.Phase == types.ExecutorTaskPhaseNotStarted {
		activeTasks := e.runningTasks.len()
		// don't start task if we have reached the active tasks limit (they will be retried
		// on next taskUpdater calls)
		if activeTasks > e.c.ActiveTasksLimit {
			return
		}
		rtCtx, rtCancel := context.WithCancel(ctx)
		rt := &runningTask{
			et:     et,
			ctx:    rtCtx,
			cancel: rtCancel,
		}

		if !e.runningTasks.addIfNotExists(et.ID, rt) {
			e.log.Warn().Msgf("task %s already running, this shouldn't happen", et.ID)
			return
		}

		go e.executeTask(rt)
	}
}

func (e *Executor) tasksDataCleanerLoop(ctx context.Context) {
	for {
		e.log.Debug().Msgf("tasksDataCleaner")

		if err := e.tasksDataCleaner(ctx); err != nil {
			e.log.Err(err).Send()
		}

		sleepCh := time.NewTimer(2 * time.Second).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (e *Executor) tasksDataCleaner(ctx context.Context) error {
	entries, err := os.ReadDir(e.tasksDir())
	if err != nil {
		return errors.WithStack(err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		etID := entry.Name()

		_, resp, err := e.runserviceClient.GetExecutorTask(ctx, e.id, etID)
		if err != nil {
			if resp == nil {
				return errors.WithStack(err)
			}
			if resp.StatusCode != http.StatusNotFound {
				return errors.WithStack(err)
			}
		}
		if resp.StatusCode == http.StatusNotFound {
			taskDir := e.taskPath(etID)
			e.log.Info().Msgf("removing task dir %q", taskDir)
			// remove task dir
			if err := os.RemoveAll(taskDir); err != nil {
				return errors.WithStack(err)
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
	ctx    context.Context
	cancel context.CancelFunc

	et *rsapitypes.ExecutorTask

	pod driver.Pod

	// timedout is used to know when the task is timedout
	timedout bool

	// podStartTime is used to know when the pod is started
	podStartTime *time.Time

	sync.Mutex
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

func (r *runningTasks) ids() []string {
	ids := []string{}
	r.m.Lock()
	defer r.m.Unlock()
	for id := range r.tasks {
		ids = append(ids, id)
	}
	return ids
}

func (e *Executor) handleTasks(ctx context.Context, c <-chan *rsapitypes.ExecutorTask) {
	for et := range c {
		e.tasksUpdaterMutex.Lock()
		e.taskUpdater(ctx, et)
		e.tasksUpdaterMutex.Unlock()
	}
}

func (e *Executor) getExecutorID() (string, error) {
	id, err := os.ReadFile(e.executorIDPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", errors.WithStack(err)
	}
	return string(id), nil
}

func (e *Executor) saveExecutorID(id string) error {
	if err := common.WriteFileAtomic(e.executorIDPath(), []byte(id), 0660); err != nil {
		return errors.Wrapf(err, "failed to write executor id file")
	}
	return nil
}

type Executor struct {
	log              zerolog.Logger
	c                *config.Executor
	runserviceClient *rsclient.Client
	id               string
	runningTasks     *runningTasks
	driver           driver.Driver
	listenAddress    string
	listenURL        string
	dynamic          bool

	tasksUpdaterMutex sync.Mutex
}

func NewExecutor(ctx context.Context, log zerolog.Logger, c *config.Executor) (*Executor, error) {
	if c.Debug {
		log = log.Level(zerolog.DebugLevel)
	}

	var err error
	c.ToolboxPath, err = filepath.Abs(c.ToolboxPath)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot determine \"agola-toolbox\" absolute path")
	}

	e := &Executor{
		log:              log,
		c:                c,
		runserviceClient: rsclient.NewClient(c.RunserviceURL, c.RunserviceAPIToken),
		runningTasks: &runningTasks{
			tasks: make(map[string]*runningTask),
		},
	}

	if err := os.MkdirAll(e.tasksDir(), 0770); err != nil {
		return nil, errors.WithStack(err)
	}

	id, err := e.getExecutorID()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if id == "" {
		id = uuid.Must(uuid.NewV4()).String()
		if err := e.saveExecutorID(id); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	e.id = id

	// TODO(sgotti) now the first available private ip will be used and the executor will bind to the wildcard address
	// improve this to let the user define the bind and the advertize address
	addr, err := sockaddr.GetPrivateIP()
	if err != nil {
		return nil, errors.Wrapf(err, "cannot discover executor listen address")
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
		return nil, errors.Wrapf(err, "cannot get web listen port")
	}
	u.Host = net.JoinHostPort(addr, port)
	e.listenURL = u.String()

	e.listenAddress = fmt.Sprintf(":%s", port)

	var initDockerConfig *registry.DockerConfig

	if e.c.InitImage.Auth != nil {
		regName, err := registry.GetRegistry(e.c.InitImage.Image)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		dockerAuthConfig :=
			registry.DockerRegistryAuth{
				Type:     registry.DockerRegistryAuthType(e.c.InitImage.Auth.Type),
				Username: e.c.InitImage.Auth.Username,
				Password: e.c.InitImage.Auth.Password,
				Auth:     e.c.InitImage.Auth.Auth,
			}
		initDockerConfig, err = registry.GenDockerConfig(map[string]registry.DockerRegistryAuth{regName: dockerAuthConfig}, []string{e.c.InitImage.Image})
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	var d driver.Driver
	switch c.Driver.Type {
	case config.DriverTypeDocker:
		d, err = driver.NewDockerDriver(log, e.id, e.c.ToolboxPath, e.c.InitImage.Image, initDockerConfig)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create docker driver")
		}
	case config.DriverTypeK8s:
		d, err = driver.NewK8sDriver(log, e.id, c.ToolboxPath, e.c.InitImage.Image, initDockerConfig)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create kubernetes driver")
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
		return errors.WithStack(err)
	}

	ch := make(chan *rsapitypes.ExecutorTask)
	schedulerHandler := NewTaskSubmissionHandler(ch)
	logsHandler := NewLogsHandler(e.log, e)
	archivesHandler := NewArchivesHandler(e)

	authHandler := handlers.NewInternalAuthChecker(e.log, e.c.APIToken)

	router := mux.NewRouter()
	apirouter := router.PathPrefix("/api/v1alpha").Subrouter()

	apirouter.Use(authHandler)

	apirouter.Handle("/executor", schedulerHandler).Methods("POST")
	apirouter.Handle("/executor/logs", logsHandler).Methods("GET")
	apirouter.Handle("/executor/archives", archivesHandler).Methods("GET")

	go e.executorStatusSenderLoop(ctx)
	go e.executorTasksStatusSenderLoop(ctx)
	go e.podsCleanerLoop(ctx)
	go e.tasksUpdaterLoop(ctx)
	go e.tasksDataCleanerLoop(ctx)
	go e.tasksTimeoutCleanerLoop(ctx)

	go e.handleTasks(ctx, ch)

	httpServer := http.Server{
		Addr:    e.listenAddress,
		Handler: apirouter,
	}
	lerrCh := make(chan error)
	go func() {
		if !e.c.Web.TLS {
			lerrCh <- httpServer.ListenAndServe()
		} else {
			lerrCh <- httpServer.ListenAndServeTLS("", "")
		}
	}()

	select {
	case <-ctx.Done():
		log.Info().Msgf("runservice executor exiting")
		httpServer.Close()
	case err := <-lerrCh:
		if err != nil {
			log.Err(err).Msgf("http server listen error")
			return errors.WithStack(err)
		}
	}

	return nil
}

func (e *Executor) tasksTimeoutCleanerLoop(ctx context.Context) {
	for {
		e.log.Debug().Msgf("tasksTimeoutCleaner")

		e.tasksTimeoutCleaner()

		sleepCh := time.NewTimer(tasksTimeoutCleanerInterval).C
		select {
		case <-ctx.Done():
			return
		case <-sleepCh:
		}
	}
}

func (e *Executor) tasksTimeoutCleaner() {
	for _, rtID := range e.runningTasks.ids() {
		rt, ok := e.runningTasks.get(rtID)
		if !ok {
			continue
		}

		rt.Lock()
		if rt.et.Spec.TaskTimeoutInterval != 0 && rt.podStartTime != nil && time.Since(*rt.podStartTime) > rt.et.Spec.TaskTimeoutInterval {
			rt.timedout = true
			rt.cancel()
		}
		rt.Unlock()
	}
}
