package k8s

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

var (
	timeout            = 8 * time.Second
	projectIDLabel     = "lagoon.sh/projectId"
	environmentIDLabel = "lagoon.sh/environmentId"
)

// Client is a k8s client.
type Client struct {
	config    *rest.Config
	clientset *kubernetes.Clientset
}

// NewClient creates a new kubernetes API client.
func NewClient() (*Client, error) {
	// create the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &Client{
		config:    config,
		clientset: clientset,
	}, nil
}

func intFromLabel(labels map[string]string, label string) (int, error) {
	var value string
	var ok bool
	if value, ok = labels[label]; !ok {
		return 0, fmt.Errorf("no such label")
	}
	return strconv.Atoi(value)
}

// NamespaceDetails gets the details for a Lagoon namespace.
// It performs some sanity checks to validate that the namespace is actually a
// Lagoon namespace.
func (c *Client) NamespaceDetails(name string) (int, int, error) {
	var pid, eid int
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ns, err := c.clientset.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return 0, 0, fmt.Errorf("couldn't get namespace: %v", err)
	}
	if pid, err = intFromLabel(ns.Labels, projectIDLabel); err != nil {
		return 0, 0, fmt.Errorf("couldn't get project ID from label: %v", err)
	}
	if eid, err = intFromLabel(ns.Labels, environmentIDLabel); err != nil {
		return 0, 0, fmt.Errorf("couldn't get environment ID from label: %v", err)
	}
	return pid, eid, nil
}

func (c *Client) podName(ctx context.Context, deployment,
	namespace string) (string, error) {
	d, err := c.clientset.AppsV1().Deployments(namespace).Get(ctx, deployment,
		metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	pods, err := c.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.FormatLabels(d.Spec.Selector.MatchLabels),
	})
	if err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pods for deployment: %s", deployment)
	}
	return pods.Items[0].Name, nil
}

// Exec joins the given streams to the command or, if command is empty, to a
// shell running in the given pod.
func (c *Client) Exec(ctx context.Context, deployment, namespace string,
	command []string, stdio io.ReadWriter, stderr io.Writer, tty bool) error {
	// get the name of the first pod in the deployment
	podName, err := c.podName(ctx, deployment, namespace)
	if err != nil {
		return fmt.Errorf("couldn't get pod name: %v", err)
	}
	// check the command. if there isn't one, give the user a shell.
	if len(command) == 0 {
		command = []string{"sh"}
	}
	// construct the request
	req := c.clientset.CoreV1().RESTClient().Post().Namespace(namespace).
		Resource("pods").Name(podName).SubResource("exec")
	req.VersionedParams(
		&v1.PodExecOptions{
			Command: command,
			Stdin:   true,
			Stdout:  true,
			Stderr:  true,
			TTY:     tty,
		},
		scheme.ParameterCodec,
	)
	// construct the executor
	exec, err := remotecommand.NewSPDYExecutor(c.config, "POST", req.URL())
	if err != nil {
		return err
	}
	// execute the command
	return exec.Stream(remotecommand.StreamOptions{
		Stdin:  stdio,
		Stdout: stdio,
		Stderr: stderr,
	})
}
