// Package k8s provides an interface to Kubernetes for common Lagoon operations.
package k8s

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/gliderlabs/ssh"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// podContainer returns the first pod and first container inside that pod for
// the given namespace and deployment.
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
	if len(pods.Items) == 0 {
		return "", "", fmt.Errorf("no pods for deployment %s", deployment)
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
		if len(pods.Items) == 0 {
			return false, nil
		}
		return pods.Items[0].Status.Phase == "Running", nil
	}
}

// unidleReplicas checks the unidle-replicas annotation for the number of
// replicas to restore. If the label cannot be read or parsed, 1 is returned.
// The return value is clamped to the interval [1,16].
func unidleReplicas(deploy appsv1.Deployment) int {
	rs, ok := deploy.Annotations["idling.amazee.io/unidle-replicas"]
	if !ok {
		return 1
	}
	r, err := strconv.Atoi(rs)
	if err != nil || r < 1 {
		return 1
	}
	if r > 16 {
		return 16
	}
	return r
}

// unidleNamespace scales all deployments with the
// "idling.amazee.io/watch=true" label up to the number of replicas in the
// "idling.amazee.io/unidle-replicas" label.
func (c *Client) unidleNamespace(ctx context.Context, namespace string) error {
	deploys, err := c.clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "idling.amazee.io/watch=true",
	})
	if err != nil {
		return fmt.Errorf("couldn't select deploys by label: %v", err)
	}
	for _, deploy := range deploys.Items {
		// check if idled
		s, err := c.clientset.AppsV1().Deployments(namespace).
			GetScale(ctx, deploy.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("couldn't get deployment scale: %v", err)
		}
		if s.Spec.Replicas > 0 {
			continue
		}
		// scale up the deployment
		sc := *s
		sc.Spec.Replicas = int32(unidleReplicas(deploy))
		_, err = c.clientset.AppsV1().Deployments(namespace).
			UpdateScale(ctx, deploy.Name, &sc, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("couldn't scale deployment: %v", err)
		}
	}
	return nil
}

func (c *Client) ensureScaled(ctx context.Context, namespace, deployment string) error {
	// get current scale
	s, err := c.clientset.AppsV1().Deployments(namespace).
		GetScale(ctx, deployment, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("couldn't get deployment scale: %v", err)
	}
	// scale up the deployment if required
	if s.Spec.Replicas == 0 {
		sc := *s
		sc.Spec.Replicas = 1
		_, err = c.clientset.AppsV1().Deployments(namespace).
			UpdateScale(ctx, deployment, &sc, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("couldn't scale deployment: %v", err)
		}
	}
	// wait for a pod to start running
	return wait.PollImmediateWithContext(ctx, time.Second, timeout,
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
	// unidle the entire namespace asynchronously
	if err := c.unidleNamespace(ctx, namespace); err != nil {
		return nil, fmt.Errorf("couldn't unidle namespace: %v", err)
	}
	// ensure the target deployment has at least one replica
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
	// execute the command
	return exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:             stdio,
		Stdout:            stdio,
		Stderr:            stderr,
		Tty:               tty,
		TerminalSizeQueue: newTermSizeQueue(ctx, winch),
	})
}
