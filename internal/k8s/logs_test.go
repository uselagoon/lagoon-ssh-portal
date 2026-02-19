package k8s

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestLinewiseCopy(t *testing.T) {
	var testCases = map[string]struct {
		input  string
		expect []string
		prefix string
	}{
		"logs": {
			input:  "foo\nbar\nbaz\n",
			expect: []string{"test: foo", "test: bar", "test: baz"},
			prefix: "test:",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			out := make(chan string, 1)
			in := io.NopCloser(strings.NewReader(tc.input))
			go linewiseCopy(tt.Context(), tc.prefix, out, in)
			timer := time.NewTimer(500 * time.Millisecond)
			var lines []string
		loop:
			for {
				select {
				case <-timer.C:
					break loop
				case line := <-out:
					lines = append(lines, line)
				}
			}
			assert.Equal(tt, tc.expect, lines, name)
		})
	}
}

func TestLagoonContainerLogs(t *testing.T) {
	testNS := "testns"
	testDeploy := "foo"
	testPod := "bar"
	deploys := &appsv1.DeploymentList{
		Items: []appsv1.Deployment{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testDeploy,
					Namespace: testNS,
					Labels: map[string]string{
						"idling.lagoon.sh/watch": "true",
					},
				},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app.kubernetes.io/name": "foo-app",
						},
					},
				},
			},
		},
	}
	pods := &corev1.PodList{
		Items: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo-123xyz",
					Namespace: testNS,
					Labels: map[string]string{
						"app.kubernetes.io/name": "foo-app",
					},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name: testPod,
						},
					},
				},
			},
		},
	}
	var testCases = map[string]struct {
		follow        bool
		sessionCount  uint
		expectError   bool
		expectedError error
	}{
		"no follow": {
			sessionCount: 1,
		},
		"no follow two sessions": {
			sessionCount: 2,
		},
		"no follow session count limit exceeded": {
			sessionCount:  3,
			expectError:   true,
			expectedError: ErrConcurrentLogLimit,
		},
		"follow session timeout": {
			follow:        true,
			sessionCount:  1,
			expectError:   true,
			expectedError: ErrLogTimeLimit,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			// create fake Kubernetes client with test deploys
			c := &Client{
				clientset:    fake.NewClientset(deploys, pods),
				logSem:       semaphore.NewWeighted(int64(2)),
				logTimeLimit: time.Second,
			}
			// execute test
			var buf bytes.Buffer
			var eg errgroup.Group
			for range tc.sessionCount {
				eg.Go(func() error {
					return c.LagoonContainerLogs(
						tt.Context(), testNS, testDeploy, testPod, tc.follow, 10, &buf)
				})
			}
			// check results
			err := eg.Wait()
			if tc.expectError {
				assert.Error(tt, err, name)
				assert.Equal(tt, err, tc.expectedError, name)
			} else {
				assert.NoError(tt, err, name)
				tt.Log(buf.String())
			}
		})
	}
}

func TestLagoonSystemLogs(t *testing.T) {
	testNS := "testns"
	testBuildPod := "lagoon-build-123xyz"
	testBuildContainer := "buildcon"
	testBuildName := "bobTheBuild"
	testTaskPod := "lagoon-task-123xyz"
	testTaskContainer := "taskcon"
	testTaskName := "mySpecialTask"
	pods := &corev1.PodList{
		Items: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testBuildPod,
					Namespace: testNS,
					Labels: map[string]string{
						lagoonJobTypeLabel:   "build",
						lagoonBuildNameLabel: testBuildName,
					},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name: testBuildContainer,
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testTaskPod,
					Namespace: testNS,
					Labels: map[string]string{
						lagoonJobTypeLabel:  "task",
						lagoonTaskNameLabel: testTaskName,
					},
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{
							Name: testTaskContainer,
						},
					},
				},
			},
		},
	}
	var testCases = map[string]struct {
		lagoonSystem  lagoon.SystemLogsType
		jobName       string
		follow        bool
		sessionCount  uint
		expectError   bool
		expectedError error
	}{
		"no follow all builds": {
			lagoonSystem: lagoon.Build,
			sessionCount: 1,
		},
		"no follow named build": {
			lagoonSystem: lagoon.Build,
			jobName:      testBuildName,
			sessionCount: 1,
		},
		"no follow all tasks": {
			lagoonSystem: lagoon.Task,
			sessionCount: 1,
		},
		"no follow named task": {
			lagoonSystem: lagoon.Task,
			jobName:      testTaskName,
			sessionCount: 1,
		},
		"no follow all builds two sessions": {
			lagoonSystem: lagoon.Build,
			sessionCount: 2,
		},
		"no follow all builds session count limit exceeded": {
			lagoonSystem:  lagoon.Build,
			sessionCount:  3,
			expectError:   true,
			expectedError: ErrConcurrentLogLimit,
		},
		"no follow all tasks session session timeout": {
			lagoonSystem:  lagoon.Task,
			follow:        true,
			sessionCount:  1,
			expectError:   true,
			expectedError: ErrLogTimeLimit,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			// create fake Kubernetes client with test pods
			c := &Client{
				clientset:    fake.NewClientset(pods),
				logSem:       semaphore.NewWeighted(int64(2)),
				logTimeLimit: time.Second,
			}
			// execute test
			var buf bytes.Buffer
			var eg errgroup.Group
			for range tc.sessionCount {
				eg.Go(func() error {
					return c.LagoonSystemLogs(
						tt.Context(), testNS, tc.lagoonSystem.String(), tc.jobName, tc.follow, 10, &buf)
				})
			}
			// check results
			err := eg.Wait()
			if tc.expectError {
				assert.Error(tt, err, name)
				assert.Equal(tt, err, tc.expectedError, name)
			} else {
				assert.NoError(tt, err, name)
				var podName, containerName string
				switch tc.lagoonSystem {
				case lagoon.Build:
					podName = testBuildPod
					containerName = testBuildContainer
				case lagoon.Task:
					podName = testTaskPod
					containerName = testTaskContainer
				default:
					tt.Fatal(tc.lagoonSystem)
				}
				assert.HasPrefix(tt, buf.String(), fmt.Sprintf("[pod/%s/%s] ", podName, containerName), name)
				tt.Log(buf.String())
			}
		})
	}
}
