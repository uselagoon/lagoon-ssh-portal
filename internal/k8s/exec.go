package k8s

import (
	"context"
	"fmt"
	"io"
	"time"

	v1 "k8s.io/api/core/v1"
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

func (c *Client) ensureScaled(ctx context.Context, namespace, deployment string) error {
	// get current scale
	s, err := c.clientset.AppsV1().Deployments(namespace).
		GetScale(ctx, deployment, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("couldn't get deployment scale: %v", err)
	}
	// exit early if no change required
	if s.Spec.Replicas > 0 {
		return nil
	}
	// scale up the deployment
	sc := *s
	sc.Spec.Replicas = 1
	_, err = c.clientset.AppsV1().Deployments(namespace).
		UpdateScale(ctx, deployment, &sc, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("couldn't scale deployment: %v", err)
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
	// ensure the deployment has at least one replica
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
	// check the command. if there isn't one, give the user a shell.
	if len(command) == 0 {
		command = []string{"sh"}
	}
	// construct the request
	req := c.clientset.CoreV1().RESTClient().Post().Namespace(namespace).
		Resource("pods").Name(firstPod).SubResource("exec")
	req.VersionedParams(
		&v1.PodExecOptions{
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
	tty bool) error {
	exec, err := c.getExecutor(ctx, namespace, deployment, container, command,
		stderr, tty)
	if err != nil {
		return fmt.Errorf("couldn't get executor: %v", err)
	}
	// execute the command
	return exec.Stream(remotecommand.StreamOptions{
		Stdin:  stdio,
		Stdout: stdio,
		Stderr: stderr,
	})
}
