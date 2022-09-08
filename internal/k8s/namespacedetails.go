package k8s

import (
	"context"
	"fmt"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	environmentIDLabel   = "lagoon.sh/environmentId"
	environmentNameLabel = "lagoon.sh/environment"
	projectIDLabel       = "lagoon.sh/projectId"
	projectNameLabel     = "lagoon.sh/project"
)

func intFromLabel(labels map[string]string, label string) (int, error) {
	var value string
	var ok bool
	if value, ok = labels[label]; !ok {
		return 0, fmt.Errorf("no such label")
	}
	return strconv.Atoi(value)
}

// NamespaceDetails gets the environment ID, project ID, and project name from
// the labels on a Lagoon environment namespace for a Lagoon namespace. If one
// of the expected labels is missing or cannot be parsed, it will return an
// error.
func (c *Client) NamespaceDetails(ctx context.Context, name string) (
	int, int, string, string, error) {
	var eid, pid int
	var ename, pname string
	var ok bool
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ns, err := c.clientset.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return 0, 0, "", "", fmt.Errorf("couldn't get namespace: %v", err)
	}
	if eid, err = intFromLabel(ns.Labels, environmentIDLabel); err != nil {
		return 0, 0, "", "", fmt.Errorf("couldn't get environment ID from label: %v", err)
	}
	if pid, err = intFromLabel(ns.Labels, projectIDLabel); err != nil {
		return 0, 0, "", "", fmt.Errorf("couldn't get project ID from label: %v", err)
	}
	if ename, ok = ns.Labels[environmentNameLabel]; !ok {
		return 0, 0, "", "", fmt.Errorf("missing environment name label %v",
			environmentNameLabel)
	}
	if pname, ok = ns.Labels[projectNameLabel]; !ok {
		return 0, 0, "", "", fmt.Errorf("missing project name label %v", projectNameLabel)
	}
	return eid, pid, ename, pname, nil
}
