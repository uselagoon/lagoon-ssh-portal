// Package k8s provides an interface to Kubernetes for common Lagoon operations.
package k8s

import (
	"context"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/gliderlabs/ssh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

const (
	// idledLabelLagoon and idledLabelAmazee mark a namespace as idled by
	// aergia-controller.
	idledLabelLagoon = "idling.lagoon.sh/idled"
	idledLabelAmazee = "idling.amazee.io/idled"
	// controlConfigMap is the name of the ConfigMap in a namespace used to
	// send requests to aergia-controller.
	controlConfigMap = "aergia-control"
	// controlLabel must be set to "true" on the control ConfigMap.
	controlLabel = "idling.lagoon.sh/control"
	// unidleKey is the control ConfigMap data key patched to "true" to request
	// that aergia-controller unidle the namespace.
	unidleKey = "unidle"
)

// podContainer returns the first running pod and first container inside that
// pod for the given namespace and deployment.
func (c *Client) podContainer(ctx context.Context, namespace,
	deployment string) (string, string, error) {
	d, err := c.clientset.AppsV1().Deployments(namespace).Get(ctx, deployment,
		metav1.GetOptions{})
	if err != nil {
		return "", "", err
	}
	pods, err := c.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.FormatLabels(d.Spec.Selector.MatchLabels),
	})
	if err != nil {
		return "", "", err
	}
	pods.Items = slices.DeleteFunc(pods.Items, func(pod corev1.Pod) bool {
		return pod.Status.Phase != "Running"
	})
	if len(pods.Items) == 0 {
		return "", "", fmt.Errorf("no running pods for deployment %s", deployment)
	}
	if len(pods.Items[0].Spec.Containers) == 0 {
		return "", "", fmt.Errorf("no containers for pod %s in deployment %s",
			pods.Items[0].Name, deployment)
	}
	return pods.Items[0].Name, pods.Items[0].Spec.Containers[0].Name, nil
}

func (c *Client) hasRunningPod(ctx context.Context,
	namespace, deployment string) wait.ConditionWithContextFunc {
	return func(context.Context) (bool, error) {
		d, err := c.clientset.AppsV1().Deployments(namespace).Get(ctx, deployment,
			metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		pods, err := c.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: labels.FormatLabels(d.Spec.Selector.MatchLabels),
		})
		if err != nil {
			return false, err
		}
		return slices.ContainsFunc(pods.Items, func(pod corev1.Pod) bool {
			return pod.Status.Phase == "Running"
		}), nil
	}
}

// requestUnidle asks aergia-controller to unidle the namespace by patching
// the control ConfigMap. It is a no-op if the namespace is not labelled idled
// and the target deployment is already running. If the ConfigMap does not
// exist (for example a namespace idled only at the CLI level), the request is
// skipped and the caller falls back to scaling the target directly.
func (c *Client) requestUnidle(ctx context.Context, namespace,
	deployment string) error {
	ns, err := c.clientset.CoreV1().Namespaces().Get(ctx, namespace,
		metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("couldn't get namespace: %v", err)
	}
	idled := ns.Labels[idledLabelLagoon] == "true" ||
		ns.Labels[idledLabelAmazee] == "true"
	if !idled {
		s, err := c.clientset.AppsV1().Deployments(namespace).
			GetScale(ctx, deployment, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("couldn't get deployment scale: %v", err)
		}
		if s.Spec.Replicas > 0 {
			return nil
		}
	}
	cm, err := c.clientset.CoreV1().ConfigMaps(namespace).Get(ctx,
		controlConfigMap, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("couldn't get %s configmap: %v", controlConfigMap, err)
	}
	if cm.Labels[controlLabel] != "true" {
		return nil
	}
	patch := fmt.Sprintf(`{"data":{%q:"true"}}`, unidleKey)
	_, err = c.clientset.CoreV1().ConfigMaps(namespace).Patch(ctx,
		controlConfigMap, types.MergePatchType, []byte(patch),
		metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("couldn't patch %s configmap: %v", controlConfigMap,
			err)
	}
	return nil
}

// ensureScaled scales the target deployment up to one replica if it is still
// at zero, then waits for a pod to start running. This covers deployments
// outside aergia-controller's selection (legacy labels, CLI-only idling).
func (c *Client) ensureScaled(ctx context.Context, namespace,
	deployment string) error {
	s, err := c.clientset.AppsV1().Deployments(namespace).
		GetScale(ctx, deployment, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("couldn't get deployment scale: %v", err)
	}
	if s.Spec.Replicas == 0 {
		sc := *s
		sc.Spec.Replicas = 1
		_, err = c.clientset.AppsV1().Deployments(namespace).
			UpdateScale(ctx, deployment, &sc, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("couldn't scale deployment: %v", err)
		}
	}
	return wait.PollUntilContextTimeout(ctx, time.Second, timeout, true,
		c.hasRunningPod(ctx, namespace, deployment))
}

// getExecutor prepares the environment by ensuring pods are scaled etc. and
// returns an executor object.
func (c *Client) getExecutor(ctx context.Context, namespace, deployment,
	container string, command []string, stderr io.Writer,
	tty bool) (remotecommand.Executor, error) {
	// If there's a tty, then animate a spinner if this function takes too long
	// to return.
	// Defer context cancel() after wg.Wait() because we need the context to
	// cancel first in order to shortcut spinAfter() and avoid a spinner if shell
	// acquisition is fast enough.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	if tty {
		wg := spinAfter(ctx, stderr, 2*time.Second)
		defer wg.Wait()
	}
	defer cancel()
	// request unidling of the namespace if idled
	if err := c.requestUnidle(ctx, namespace, deployment); err != nil {
		return nil, fmt.Errorf("couldn't unidle namespace: %v", err)
	}
	// wait for the target deployment to have a running pod
	if err := c.ensureScaled(ctx, namespace, deployment); err != nil {
		return nil, fmt.Errorf("couldn't scale deployment: %v", err)
	}
	// get the name of the first pod and first container
	firstPod, firstContainer, err := c.podContainer(ctx, namespace, deployment)
	if err != nil {
		return nil, fmt.Errorf("couldn't get pod name: %v", err)
	}
	// check if we were given a container. If not, use the first container found.
	if container == "" {
		container = firstContainer
	}
	// construct the request
	req := c.clientset.CoreV1().RESTClient().Post().Namespace(namespace).
		Resource("pods").Name(firstPod).SubResource("exec")
	req.VersionedParams(
		&corev1.PodExecOptions{
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       tty,
			Container: container,
			Command:   command,
		},
		scheme.ParameterCodec,
	)
	// construct the executor
	return remotecommand.NewSPDYExecutor(c.config, "POST", req.URL())
}

// Exec takes a target namespace, deployment, command, and IO streams, and
// joins the streams to the command, or if command is empty to an interactive
// shell, running in a pod inside the deployment.
func (c *Client) Exec(ctx context.Context, namespace, deployment,
	container string, command []string, stdio io.ReadWriter, stderr io.Writer,
	tty bool, winch <-chan ssh.Window) error {
	exec, err := c.getExecutor(ctx, namespace, deployment, container, command,
		stderr, tty)
	if err != nil {
		return fmt.Errorf("couldn't get executor: %v", err)
	}
	// Ensure the TerminalSizeQueue goroutine is cancelled immediately after
	// command exection completes by deferring its cancellation here.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// execute the command
	return exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:             stdio,
		Stdout:            stdio,
		Stderr:            stderr,
		Tty:               tty,
		TerminalSizeQueue: newTermSizeQueue(ctx, winch),
	})
}
