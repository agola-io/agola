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
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"agola.io/agola/internal/util"
	"agola.io/agola/services/types"

	"github.com/docker/docker/pkg/archive"
	uuid "github.com/satori/go.uuid"
	"go.uber.org/zap"
	errors "golang.org/x/xerrors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apilabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	coordinationlistersv1 "k8s.io/client-go/listers/coordination/v1"
	listerscorev1 "k8s.io/client-go/listers/core/v1"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	utilexec "k8s.io/utils/exec"
)

const (
	mainContainerName = "maincontainer"

	configMapName       = "agola-executors-group"
	executorLeasePrefix = "agola-executor-"
	podNamePrefix       = "agola-task-"

	executorsGroupIDKey          = labelPrefix + "executorsgroupid"
	executorsGroupIDConfigMapKey = "executorsgroupid"
	cmLeaseKey                   = labelPrefix + "lease"

	renewExecutorLeaseInterval = 10 * time.Second
	staleExecutorLeaseInterval = 1 * time.Minute
	informerResyncInterval     = 10 * time.Second

	k8sLabelArchBeta = "beta.kubernetes.io/arch"
)

type K8sDriver struct {
	log              *zap.SugaredLogger
	restconfig       *restclient.Config
	client           *kubernetes.Clientset
	toolboxPath      string
	namespace        string
	executorID       string
	executorsGroupID string
	useLeaseAPI      bool
	nodeLister       listerscorev1.NodeLister
	podLister        listerscorev1.PodLister
	cmLister         listerscorev1.ConfigMapLister
	leaseLister      coordinationlistersv1.LeaseLister
	k8sLabelArch     string
}

type K8sPod struct {
	id        string
	namespace string
	labels    map[string]string

	restconfig    *restclient.Config
	client        *kubernetes.Clientset
	initVolumeDir string
}

func NewK8sDriver(logger *zap.Logger, executorID, toolboxPath string) (*K8sDriver, error) {
	kubeClientConfig := NewKubeClientConfig("", "", "")
	kubecfg, err := kubeClientConfig.ClientConfig()
	if err != nil {
		return nil, err
	}
	kubecli, err := kubernetes.NewForConfig(kubecfg)
	if err != nil {
		return nil, fmt.Errorf("cannot create kubernetes client: %v", err)
	}

	namespace, _, err := kubeClientConfig.Namespace()
	if err != nil {
		return nil, err
	}

	d := &K8sDriver{
		log:          logger.Sugar(),
		restconfig:   kubecfg,
		client:       kubecli,
		toolboxPath:  toolboxPath,
		namespace:    namespace,
		executorID:   executorID,
		k8sLabelArch: corev1.LabelArchStable,
	}

	serverVersion, err := d.client.Discovery().ServerVersion()
	if err != nil {
		return nil, err
	}
	sv, err := parseGitVersion(serverVersion.GitVersion)
	// if server version parsing fails just warn but ignore it
	if err != nil {
		d.log.Warnf("failed to parse k8s server version: %v", err)
	}
	if sv != nil {
		// for k8s version < v1.14.x use old arch label
		if sv.Major == 1 && sv.Minor < 14 {
			d.k8sLabelArch = k8sLabelArchBeta
		}
	}

	lists, err := d.client.Discovery().ServerPreferredResources()
	if err != nil {
		return nil, err
	}

	hasLeaseAPI := false
	for _, list := range lists {
		if len(list.APIResources) == 0 {
			continue
		}
		if list.GroupVersion != "coordination.k8s.io/v1" {
			continue
		}
		for _, apiResource := range list.APIResources {
			if apiResource.Kind == "Lease" {
				hasLeaseAPI = true
			}
		}
	}
	d.useLeaseAPI = hasLeaseAPI

	executorsGroupID, err := d.getOrCreateExecutorsGroupID(context.TODO())
	if err != nil {
		return nil, err
	}

	d.executorsGroupID = executorsGroupID

	ctx := context.TODO()
	factory := informers.NewSharedInformerFactoryWithOptions(d.client, informerResyncInterval, informers.WithNamespace(d.namespace))

	nodeInformer := factory.Core().V1().Nodes()
	d.nodeLister = nodeInformer.Lister()
	go nodeInformer.Informer().Run(ctx.Done())

	podInformer := factory.Core().V1().Pods()
	d.podLister = podInformer.Lister()
	go podInformer.Informer().Run(ctx.Done())

	if d.useLeaseAPI {
		leaseInformer := factory.Coordination().V1().Leases()
		d.leaseLister = leaseInformer.Lister()
		go leaseInformer.Informer().Run(ctx.Done())
	} else {
		cmInformer := factory.Core().V1().ConfigMaps()
		d.cmLister = cmInformer.Lister()
		go cmInformer.Informer().Run(ctx.Done())
	}

	go func() {
		for {
			if err := d.updateLease(ctx); err != nil {
				d.log.Errorf("failed to update executor lease: %+v", err)
			}

			select {
			case <-ctx.Done():
				return
			default:
			}

			time.Sleep(renewExecutorLeaseInterval)
		}
	}()

	go func() {
		for {
			if err := d.cleanStaleExecutorsLease(ctx); err != nil {
				d.log.Errorf("failed to clean stale executors lease: %+v", err)
			}

			select {
			case <-ctx.Done():
				return
			default:
			}

			time.Sleep(renewExecutorLeaseInterval)
		}
	}()

	return d, nil
}

// NewKubeClientConfig return a kube client config that will by default use an
// in cluster client config or, if not available or overriden an external client
// config using the default client behavior used also by kubectl.
func NewKubeClientConfig(kubeconfigPath, context, namespace string) clientcmd.ClientConfig {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.DefaultClientConfig = &clientcmd.DefaultClientConfig

	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}

	overrides := &clientcmd.ConfigOverrides{ClusterDefaults: clientcmd.ClusterDefaults}

	if context != "" {
		overrides.CurrentContext = context
	}

	if namespace != "" {
		overrides.Context.Namespace = namespace
	}

	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
}

func (d *K8sDriver) Setup(ctx context.Context) error {
	return nil
}

func (d *K8sDriver) Archs(ctx context.Context) ([]types.Arch, error) {
	// TODO(sgotti) use go client listers instead of querying every time
	nodes, err := d.nodeLister.List(apilabels.SelectorFromSet(nil))
	if err != nil {
		return nil, err
	}
	archsMap := map[types.Arch]struct{}{}
	archs := []types.Arch{}
	for _, node := range nodes {
		archsMap[types.ArchFromString(node.Status.NodeInfo.Architecture)] = struct{}{}
	}
	for arch := range archsMap {
		archs = append(archs, arch)
	}

	return archs, nil
}

func (d *K8sDriver) ExecutorGroup(ctx context.Context) (string, error) {
	return d.executorsGroupID, nil
}

func (d *K8sDriver) GetExecutors(ctx context.Context) ([]string, error) {
	return d.getLeases((ctx))
}

// executorsGroups gets or creates (if it doesn't exists) a configmap under
// the k8s namespace where the executorsgroup id is saved. The executorsgroupid
// is unique per k8s namespace and is shared by all the executors accessing this
// namespace
func (d *K8sDriver) getOrCreateExecutorsGroupID(ctx context.Context) (string, error) {
	cmClient := d.client.CoreV1().ConfigMaps(d.namespace)

	// pod and secret name, based on pod id
	cm, err := cmClient.Get(configMapName, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return "", err
		}
	} else {
		return cm.Data[executorsGroupIDConfigMapKey], nil
	}

	executorsGroupID := uuid.NewV4().String()

	cm = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: configMapName,
		},
		Data: map[string]string{executorsGroupIDConfigMapKey: executorsGroupID},
	}
	if _, err = cmClient.Create(cm); err != nil {
		return "", err
	}

	return executorsGroupID, nil
}

func (d *K8sDriver) NewPod(ctx context.Context, podConfig *PodConfig, out io.Writer) (Pod, error) {
	if len(podConfig.Containers) == 0 {
		return nil, errors.Errorf("empty container config")
	}

	secretClient := d.client.CoreV1().Secrets(d.namespace)
	podClient := d.client.CoreV1().Pods(d.namespace)

	labels := map[string]string{}
	labels[agolaLabelKey] = agolaLabelValue
	labels[podIDKey] = podConfig.ID
	labels[taskIDKey] = podConfig.TaskID
	labels[executorIDKey] = d.executorID
	labels[executorsGroupIDKey] = d.executorsGroupID

	dockerconfigj, err := json.Marshal(podConfig.DockerConfig)
	if err != nil {
		return nil, err
	}

	// pod and secret name, based on pod id
	name := podNamePrefix + podConfig.ID

	// secret that hold the docker registry auth
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Data: map[string][]byte{
			".dockerconfigjson": dockerconfigj,
		},
		Type: corev1.SecretTypeDockerConfigJson,
	}

	_, err = secretClient.Create(secret)
	if err != nil {
		return nil, err
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: d.namespace,
			Name:      name,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			ImagePullSecrets: []corev1.LocalObjectReference{{Name: name}},
			// don't mount service account secrets or pods will be able to talk with k8s
			// api
			AutomountServiceAccountToken: util.BoolP(false),
			InitContainers: []corev1.Container{
				{
					Name:  "initcontainer",
					Image: "busybox",
					// wait for a file named /tmp/done and then exit
					Command: []string{"/bin/sh", "-c", "while true; do if [[ -f /tmp/done ]]; then exit; fi; sleep 1; done"},
					Stdin:   true,
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "agolavolume",
							MountPath: podConfig.InitVolumeDir,
						},
					},
				},
			},
			Containers: []corev1.Container{},
			Volumes: []corev1.Volume{
				{
					Name: "agolavolume",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
			},
		},
	}

	// define containers
	for cIndex, containerConfig := range podConfig.Containers {
		var containerName string
		if cIndex == 0 {
			containerName = mainContainerName
		} else {
			containerName = fmt.Sprintf("service%d", cIndex)
		}
		c := corev1.Container{
			Name:       containerName,
			Image:      containerConfig.Image,
			Command:    containerConfig.Cmd,
			Env:        genEnvVars(containerConfig.Env),
			Stdin:      true,
			WorkingDir: containerConfig.WorkingDir,
			// by default always try to pull the image so we are sure only authorized users can fetch them
			// see https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#alwayspullimages
			ImagePullPolicy: corev1.PullAlways,
			SecurityContext: &corev1.SecurityContext{
				Privileged: &containerConfig.Privileged,
			},
		}
		if cIndex == 0 {
			// main container requires the initvolume containing the toolbox
			c.VolumeMounts = []corev1.VolumeMount{
				{
					Name:      "agolavolume",
					MountPath: podConfig.InitVolumeDir,
					ReadOnly:  true,
				},
			}
		}

		for vIndex, cVol := range containerConfig.Volumes {
			var vol corev1.Volume
			var volMount corev1.VolumeMount
			if cVol.TmpFS != nil {
				name := fmt.Sprintf("volume-%d-%d", cIndex, vIndex)
				var sizeLimit *resource.Quantity
				if cVol.TmpFS.Size != 0 {
					sizeLimit = resource.NewQuantity(cVol.TmpFS.Size, resource.BinarySI)
				}
				vol = corev1.Volume{
					Name: name,
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							Medium:    corev1.StorageMediumMemory,
							SizeLimit: sizeLimit,
						},
					},
				}
				volMount = corev1.VolumeMount{
					Name:      name,
					MountPath: cVol.Path,
				}
			} else {
				return nil, errors.Errorf("missing volume config")
			}

			pod.Spec.Volumes = append(pod.Spec.Volumes, vol)
			c.VolumeMounts = append(c.VolumeMounts, volMount)
		}

		pod.Spec.Containers = append(pod.Spec.Containers, c)
	}

	if podConfig.Arch != "" {
		pod.Spec.NodeSelector = map[string]string{
			d.k8sLabelArch: string(podConfig.Arch),
		}
	}

	pod, err = podClient.Create(pod)
	if err != nil {
		return nil, err
	}

	watcher, err := podClient.Watch(
		metav1.SingleObject(pod.ObjectMeta),
	)
	if err != nil {
		return nil, err
	}

	// wait for init container to be ready
	for event := range watcher.ResultChan() {
		switch event.Type {
		case watch.Modified:
			pod := event.Object.(*corev1.Pod)
			if len(pod.Status.InitContainerStatuses) > 0 {
				if pod.Status.InitContainerStatuses[0].State.Running != nil {
					watcher.Stop()
				}
			}
		case watch.Deleted:
			return nil, errors.Errorf("pod %q has been deleted", pod.Name)
		}
	}

	fmt.Fprintf(out, "init container ready\n")

	coreclient, err := corev1client.NewForConfig(d.restconfig)
	if err != nil {
		return nil, err
	}

	// get the pod arch
	req := coreclient.RESTClient().
		Post().
		Namespace(pod.Namespace).
		Resource("pods").
		Name(pod.Name).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "initcontainer",
			Command:   []string{"uname", "-m"},
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(d.restconfig, "POST", req.URL())
	if err != nil {
		return nil, errors.Errorf("failed to generate k8s client spdy executor for url %q, method: POST: %w", req.URL(), err)
	}

	stdout := bytes.Buffer{}
	err = exec.Stream(remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: out,
	})
	if err != nil {
		return nil, errors.Errorf("failed to execute command on initcontainer: %w", err)
	}
	osArch := strings.TrimSpace(stdout.String())

	var arch types.Arch
	switch osArch {
	case "x86_64":
		arch = types.ArchAMD64
	case "aarch64":
		arch = types.ArchARM64
	default:
		return nil, errors.Errorf("unsupported pod arch %q", osArch)
	}

	// copy the toolbox for the pod arch
	toolboxExecPath, err := toolboxExecPath(d.toolboxPath, arch)
	if err != nil {
		return nil, errors.Errorf("failed to get toolbox path for arch %q: %w", arch, err)
	}
	srcInfo, err := archive.CopyInfoSourcePath(toolboxExecPath, false)
	if err != nil {
		return nil, err
	}
	srcInfo.RebaseName = "agola-toolbox"

	srcArchive, err := archive.TarResource(srcInfo)
	if err != nil {
		return nil, err
	}
	defer srcArchive.Close()

	req = coreclient.RESTClient().
		Post().
		Namespace(pod.Namespace).
		Resource("pods").
		Name(pod.Name).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "initcontainer",
			Command:   []string{"tar", "xf", "-", "-C", podConfig.InitVolumeDir},
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err = remotecommand.NewSPDYExecutor(d.restconfig, "POST", req.URL())
	if err != nil {
		return nil, errors.Errorf("failed to generate k8s client spdy executor for url %q, method: POST: %w", req.URL(), err)
	}

	fmt.Fprintf(out, "extracting toolbox\n")
	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  srcArchive,
		Stdout: out,
		Stderr: out,
	})
	if err != nil {
		return nil, errors.Errorf("failed to execute command on initcontainer: %w", err)
	}
	fmt.Fprintf(out, "extracting toolbox done\n")

	req = coreclient.RESTClient().
		Post().
		Namespace(pod.Namespace).
		Resource("pods").
		Name(pod.Name).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "initcontainer",
			Command:   []string{"touch", "/tmp/done"},
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err = remotecommand.NewSPDYExecutor(d.restconfig, "POST", req.URL())
	if err != nil {
		return nil, errors.Errorf("failed to generate k8s client spdy executor for url %q, method: POST: %w", req.URL(), err)
	}

	err = exec.Stream(remotecommand.StreamOptions{
		Stdout: out,
		Stderr: out,
	})
	if err != nil {
		return nil, errors.Errorf("failed to execute command on initcontainer: %w", err)
	}

	watcher, err = podClient.Watch(
		metav1.SingleObject(pod.ObjectMeta),
	)
	if err != nil {
		return nil, err
	}

	// wait for pod to be initialized
	for event := range watcher.ResultChan() {
		switch event.Type {
		case watch.Modified:
			pod := event.Object.(*corev1.Pod)
			if len(pod.Status.ContainerStatuses) > 0 {
				if pod.Status.ContainerStatuses[0].State.Running != nil {
					watcher.Stop()
				}
			}
		case watch.Deleted:
			return nil, errors.Errorf("pod %q has been deleted", pod.Name)
		}
	}

	return &K8sPod{
		id:        pod.Name,
		namespace: pod.Namespace,

		restconfig:    d.restconfig,
		client:        d.client,
		initVolumeDir: podConfig.InitVolumeDir,
	}, nil
}

func (d *K8sDriver) GetPods(ctx context.Context, all bool) ([]Pod, error) {
	// get all pods for the executor group, also the ones managed by other executors in the same executor group
	labels := map[string]string{executorsGroupIDKey: d.executorsGroupID}

	k8sPods, err := d.podLister.List(apilabels.SelectorFromSet(labels))
	if err != nil {
		return nil, err
	}

	pods := make([]Pod, len(k8sPods))
	for i, k8sPod := range k8sPods {
		labels := map[string]string{}
		// keep only labels starting with our prefix
		for n, v := range k8sPod.Labels {
			if strings.HasPrefix(n, labelPrefix) {
				labels[n] = v
			}
		}
		pods[i] = &K8sPod{
			id:        k8sPod.Name,
			namespace: k8sPod.Namespace,
			labels:    labels,

			restconfig: d.restconfig,
			client:     d.client,
		}
	}
	return pods, nil
}

func (p *K8sPod) ID() string {
	return p.id
}

func (p *K8sPod) ExecutorID() string {
	return p.labels[executorIDKey]
}

func (p *K8sPod) TaskID() string {
	return p.labels[taskIDKey]
}

func (p *K8sPod) Stop(ctx context.Context) error {
	d := int64(0)
	secretClient := p.client.CoreV1().Secrets(p.namespace)
	if err := secretClient.Delete(p.id, &metav1.DeleteOptions{GracePeriodSeconds: &d}); err != nil {
		return err
	}
	podClient := p.client.CoreV1().Pods(p.namespace)
	if err := podClient.Delete(p.id, &metav1.DeleteOptions{GracePeriodSeconds: &d}); err != nil {
		return err
	}
	return nil
}

func (p *K8sPod) Remove(ctx context.Context) error {
	return p.Stop(ctx)
}

type K8sContainerExec struct {
	endCh chan error

	stdin io.WriteCloser
}

func (p *K8sPod) Exec(ctx context.Context, execConfig *ExecConfig) (ContainerExec, error) {
	endCh := make(chan error)

	coreclient, err := corev1client.NewForConfig(p.restconfig)
	if err != nil {
		return nil, err
	}

	// k8s pod exec api doesn't let us define the workingdir and the environment.
	// Use a toolbox command that will set them up and then exec the real command.
	envj, err := json.Marshal(execConfig.Env)
	if err != nil {
		return nil, err
	}
	cmd := []string{filepath.Join(p.initVolumeDir, "agola-toolbox"), "exec", "-e", string(envj), "-w", execConfig.WorkingDir, "--"}
	cmd = append(cmd, execConfig.Cmd...)

	req := coreclient.RESTClient().
		Post().
		Namespace(p.namespace).
		Resource("pods").
		Name(p.id).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: mainContainerName,
			Command:   cmd,
			Stdin:     execConfig.AttachStdin,
			Stdout:    execConfig.Stdout != nil,
			Stderr:    execConfig.Stderr != nil,
			TTY:       execConfig.Tty,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(p.restconfig, "POST", req.URL())
	if err != nil {
		return nil, err
	}

	reader, writer := io.Pipe()

	var stdin io.Reader
	if execConfig.AttachStdin {
		stdin = reader
	}

	go func() {
		err := exec.Stream(remotecommand.StreamOptions{
			Stdin:  stdin,
			Stdout: execConfig.Stdout,
			Stderr: execConfig.Stderr,
			Tty:    execConfig.Tty,
		})
		endCh <- err
	}()

	return &K8sContainerExec{
		stdin: writer,
		endCh: endCh,
	}, nil
}

func (e *K8sContainerExec) Wait(ctx context.Context) (int, error) {
	err := <-e.endCh

	var exitCode int
	if err != nil {
		switch err := err.(type) {
		case utilexec.ExitError:
			exitCode = err.ExitStatus()
		default:
			return -1, err
		}
	}

	return exitCode, nil
}

func (e *K8sContainerExec) Stdin() io.WriteCloser {
	return e.stdin
}

func genEnvVars(env map[string]string) []corev1.EnvVar {
	envVars := make([]corev1.EnvVar, 0, len(env))
	for n, v := range env {
		envVars = append(envVars, corev1.EnvVar{Name: n, Value: v})
	}
	return envVars
}

type serverVersion struct {
	Major int
	Minor int
}

// k8s version is in this format: v0.0.0(-master+$Format:%h$)
var gitVersionRegex = regexp.MustCompile("v([0-9]+).([0-9]+).[0-9]+.*")

func parseGitVersion(gitVersion string) (*serverVersion, error) {
	parsedVersion := gitVersionRegex.FindStringSubmatch(gitVersion)
	if len(parsedVersion) != 3 {
		return nil, fmt.Errorf("cannot parse git version %s", gitVersion)
	}
	sv := &serverVersion{}
	var err error
	sv.Major, err = strconv.Atoi(parsedVersion[1])
	if err != nil {
		return nil, err
	}
	sv.Minor, err = strconv.Atoi(parsedVersion[2])
	if err != nil {
		return nil, err
	}
	return sv, nil
}
