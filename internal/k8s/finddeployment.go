package k8s

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FindDeployment searches the given namespace for a deployment with a matching
// lagoon.sh/service= label, and returns the name of that deployment.
func (c *Client) FindDeployment(ctx context.Context, namespace,
	service string) (string, error) {
	deployments, err := c.clientset.AppsV1().Deployments(namespace).
		List(ctx, metav1.ListOptions{
			LabelSelector:  fmt.Sprintf("lagoon.sh/service=%s", service),
			TimeoutSeconds: &timeoutSeconds,
		})
	if err != nil {
		return "", fmt.Errorf("couldn't list deployments: %v", err)
	}
	if len(deployments.Items) == 0 {
		return "", fmt.Errorf("couldn't find deployment for service %s", service)
	}
	return deployments.Items[0].Name, nil
}
