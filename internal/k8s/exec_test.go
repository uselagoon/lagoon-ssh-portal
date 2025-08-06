package k8s

import (
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestUnidleReplicasParsing(t *testing.T) {
	var testCases = map[string]struct {
		input  string
		expect int
	}{
		"simple":            {input: "4", expect: 4},
		"high edge":         {input: "16", expect: 16},
		"low edge":          {input: "1", expect: 1},
		"zero":              {input: "0", expect: 1},
		"too high":          {input: "17", expect: 16},
		"way too high":      {input: "17000000", expect: 16},
		"overflow too high": {input: "9223372036854775808", expect: 1},
		"too low":           {input: "-1", expect: 1},
		"way too low":       {input: "-17000000", expect: 1},
		"overflow too low":  {input: "-9223372036854775808", expect: 1},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			deploy := appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{idleReplicaAnnotations[0]: tc.input},
				},
			}
			assert.Equal(tt, tc.expect, unidleReplicas(deploy), name)
		})
	}
}

func TestUnidleReplicasLabels(t *testing.T) {
	for _, ra := range idleReplicaAnnotations {
		t.Run(ra, func(tt *testing.T) {
			deploy := appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{ra: "9"},
				},
			}
			assert.Equal(tt, 9, unidleReplicas(deploy), ra)
		})
	}
}

func deployNames(deploys *appsv1.DeploymentList) []string {
	var names []string
	if deploys == nil {
		return names // no deploys to unidle
	}
	for _, deploy := range deploys.Items {
		names = append(names, deploy.Name)
	}
	return names
}

func TestIdledDeployLabels(t *testing.T) {
	testNS := "testns"
	var testCases = map[string]struct {
		deploys *appsv1.DeploymentList
		expect  []string
	}{
		"prefer lagoon.sh": {
			deploys: &appsv1.DeploymentList{
				Items: []appsv1.Deployment{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "one",
							Namespace: testNS,
							Labels: map[string]string{
								"idling.lagoon.sh/watch": "true",
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "two",
							Namespace: testNS,
							Labels: map[string]string{
								"idling.amazee.io/watch": "true",
							},
						},
					},
				},
			},
			expect: []string{"one"},
		},
		"fall back to amazee.io": {
			deploys: &appsv1.DeploymentList{
				Items: []appsv1.Deployment{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "one",
							Namespace: testNS,
							Labels: map[string]string{
								"idling.amazee.io/watch": "true",
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "two",
							Namespace: testNS,
							Labels: map[string]string{
								"idling.amazee.io/watch": "true",
							},
						},
					},
				},
			},
			expect: []string{"one", "two"},
		},
		"ignore mislabelled deploys": {
			deploys: &appsv1.DeploymentList{
				Items: []appsv1.Deployment{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "one",
							Namespace: testNS,
							Labels: map[string]string{
								"idling.foo/watch": "true",
							},
						},
					},
				},
			},
		},
		"ignore other namespaces": {
			deploys: &appsv1.DeploymentList{
				Items: []appsv1.Deployment{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "one",
							Namespace: "wrongns",
							Labels: map[string]string{
								"idling.lagoon.sh/watch": "true",
							},
						},
					},
				},
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			// create fake Kubernetes client with test deploys
			c := &Client{
				clientset: fake.NewClientset(tc.deploys),
			}
			deploys, err := c.idledDeploys(tt.Context(), testNS)
			assert.NoError(tt, err, name)
			assert.Equal(tt, tc.expect, deployNames(deploys), name)
		})
	}
}

func TestHasRunningPod(t *testing.T) {
	testNS := "testns"
	matchLabels := map[string]string{"app": "myapp"}
	testDeploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testDeploy",
			Namespace: testNS,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: matchLabels,
			},
		},
	}
	var testCases = map[string]struct {
		pods                 *corev1.PodList
		expectHasRunningPods bool
	}{
		"one pod in Succeeded state": {
			pods: &corev1.PodList{
				Items: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-0",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Status: corev1.PodStatus{
							Phase: "Succeeded",
						},
					},
				},
			},
		},
		"one pod in Running state": {
			pods: &corev1.PodList{
				Items: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-0",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Status: corev1.PodStatus{
							Phase: "Running",
						},
					},
				},
			},
			expectHasRunningPods: true,
		},
		"multiple pods Succeeded first": {
			pods: &corev1.PodList{
				Items: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-0",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Status: corev1.PodStatus{
							Phase: "Succeeded",
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-1",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Status: corev1.PodStatus{
							Phase: "Running",
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-2",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Status: corev1.PodStatus{
							Phase: "Running",
						},
					},
				},
			},
			expectHasRunningPods: true,
		},
		"multiple pods Succeeded middle": {
			pods: &corev1.PodList{
				Items: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-0",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Status: corev1.PodStatus{
							Phase: "Running",
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-1",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Status: corev1.PodStatus{
							Phase: "Succeeded",
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-2",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Status: corev1.PodStatus{
							Phase: "Running",
						},
					},
				},
			},
			expectHasRunningPods: true,
		},
		"multiple pods Succeeded last": {
			pods: &corev1.PodList{
				Items: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-0",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Status: corev1.PodStatus{
							Phase: "Running",
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-1",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Status: corev1.PodStatus{
							Phase: "Running",
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-2",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Status: corev1.PodStatus{
							Phase: "Succeeded",
						},
					},
				},
			},
			expectHasRunningPods: true,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			c := &Client{
				clientset: fake.NewClientset(testDeploy, tc.pods),
			}
			result, err :=
				c.hasRunningPod(tt.Context(), testNS, testDeploy.Name)(tt.Context())
			assert.NoError(tt, err, name)
			if tc.expectHasRunningPods {
				assert.True(tt, result, name)
			} else {
				assert.False(tt, result, name)
			}
		})
	}
}

func TestPodContainer(t *testing.T) {
	testNS := "testns"
	matchLabels := map[string]string{"app": "myapp"}
	testDeploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testDeploy",
			Namespace: testNS,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: matchLabels,
			},
		},
	}
	testContainerStateWaiting := &corev1.ContainerStateWaiting{
		Reason:  "waiting reason",
		Message: "waiting message",
	}
	testContainerStateRunning := &corev1.ContainerStateRunning{
		StartedAt: metav1.Time{
			Time: time.Date(2025, time.August, 6, 3, 24, 33, 0, time.UTC),
		},
	}
	testContainerStateTerminated := &corev1.ContainerStateTerminated{
		Reason:  "terminated reason",
		Message: "terminated message",
		StartedAt: metav1.Time{
			Time: time.Date(2025, time.August, 6, 3, 24, 33, 0, time.UTC),
		},
		FinishedAt: metav1.Time{
			Time: time.Date(2025, time.August, 6, 3, 24, 34, 0, time.UTC),
		},
		ContainerID: "containerd://e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	var testCases = map[string]struct {
		pods                *corev1.PodList
		expectError         bool
		expectPodName       string
		expectContainerName string
	}{
		"one pod in Succeeded state": {
			pods: &corev1.PodList{
				Items: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-0",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: "container-0"},
							},
						},
						Status: corev1.PodStatus{
							Phase: "Succeeded",
							ContainerStatuses: []corev1.ContainerStatus{
								{
									Name: "my-pod-0",
									State: corev1.ContainerState{
										Terminated: testContainerStateTerminated,
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
		"one pod in Waiting state": {
			pods: &corev1.PodList{
				Items: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-0",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: "container-0"},
							},
						},
						Status: corev1.PodStatus{
							Phase: "Pending",
							ContainerStatuses: []corev1.ContainerStatus{
								{
									Name: "container-0",
									State: corev1.ContainerState{
										Waiting: testContainerStateWaiting,
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
		},
		"one pod in Running state": {
			pods: &corev1.PodList{
				Items: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-0",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: "container-0"},
							},
						},
						Status: corev1.PodStatus{
							Phase: "Running",
							ContainerStatuses: []corev1.ContainerStatus{
								{
									Name: "container-0",
									State: corev1.ContainerState{
										Running: testContainerStateRunning,
									},
								},
							},
						},
					},
				},
			},
			expectPodName:       "my-pod-0",
			expectContainerName: "container-0",
		},
		"multiple pods Succeeded first": {
			pods: &corev1.PodList{
				Items: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-0",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Status: corev1.PodStatus{
							Phase: "Succeeded",
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-1",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: "container-0"},
							},
						},
						Status: corev1.PodStatus{
							Phase: "Running",
							ContainerStatuses: []corev1.ContainerStatus{
								{
									Name: "container-0",
									State: corev1.ContainerState{
										Running: testContainerStateRunning,
									},
								},
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-2",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: "container-0"},
							},
						},
						Status: corev1.PodStatus{
							Phase: "Running",
							ContainerStatuses: []corev1.ContainerStatus{
								{
									Name: "container-0",
									State: corev1.ContainerState{
										Running: testContainerStateRunning,
									},
								},
							},
						},
					},
				},
			},
			expectPodName:       "my-pod-1",
			expectContainerName: "container-0",
		},
		"multiple pods Succeeded middle": {
			pods: &corev1.PodList{
				Items: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-0",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: "container-0"},
							},
						},
						Status: corev1.PodStatus{
							Phase: "Running",
							ContainerStatuses: []corev1.ContainerStatus{
								{
									Name: "container-0",
									State: corev1.ContainerState{
										Running: testContainerStateRunning,
									},
								},
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-1",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Status: corev1.PodStatus{
							Phase: "Succeeded",
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-2",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: "container-0"},
							},
						},
						Status: corev1.PodStatus{
							Phase: "Running",
							ContainerStatuses: []corev1.ContainerStatus{
								{
									Name: "container-0",
									State: corev1.ContainerState{
										Running: testContainerStateRunning,
									},
								},
							},
						},
					},
				},
			},
			expectPodName:       "my-pod-0",
			expectContainerName: "container-0",
		},
		"multiple pods Succeeded last": {
			pods: &corev1.PodList{
				Items: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-0",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: "container-0"},
							},
						},
						Status: corev1.PodStatus{
							Phase: "Running",
							ContainerStatuses: []corev1.ContainerStatus{
								{
									Name: "container-0",
									State: corev1.ContainerState{
										Running: testContainerStateRunning,
									},
								},
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-1",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: "container-0"},
							},
						},
						Status: corev1.PodStatus{
							Phase: "Running",
							ContainerStatuses: []corev1.ContainerStatus{
								{
									Name: "container-0",
									State: corev1.ContainerState{
										Running: testContainerStateRunning,
									},
								},
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "my-pod-2",
							Namespace: testNS,
							Labels:    matchLabels,
						},
						Status: corev1.PodStatus{
							Phase: "Succeeded",
						},
					},
				},
			},
			expectPodName:       "my-pod-0",
			expectContainerName: "container-0",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			c := &Client{
				clientset: fake.NewClientset(testDeploy, tc.pods),
			}
			podName, containerName, err :=
				c.podContainer(tt.Context(), testNS, testDeploy.Name)
			if tc.expectError {
				assert.Error(tt, err, name)
			} else {
				assert.NoError(tt, err, name)
				assert.Equal(tt, tc.expectPodName, podName, name)
				assert.Equal(tt, tc.expectContainerName, containerName, name)
			}
		})
	}
}
