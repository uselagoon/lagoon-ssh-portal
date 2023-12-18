// Package k8s wraps a Kubernetes API client with convenience methods for
// Lagoon services.
package k8s

import (
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	// timeout defines the common timeout for k8s API operations
	timeout = 90 * time.Second
)

// timeoutSeconds defines the common timeout for k8s API operations in the type
// required by metav1.ListOptions.
var timeoutSeconds = int64(timeout / time.Second)

// Client is a k8s client.
type Client struct {
	config       *rest.Config
	clientset    *kubernetes.Clientset
	logStreamIDs sync.Map
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
