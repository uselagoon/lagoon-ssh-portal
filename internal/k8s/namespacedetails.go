package k8s

import (
	"context"
	"fmt"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	projectIDLabel     = "lagoon.sh/projectId"
	environmentIDLabel = "lagoon.sh/environmentId"
)

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
func (c *Client) NamespaceDetails(ctx context.Context, name string) (int, int, error) {
	var pid, eid int
	ctx, cancel := context.WithTimeout(ctx, timeout)
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
