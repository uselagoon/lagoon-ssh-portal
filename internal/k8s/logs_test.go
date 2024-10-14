package k8s

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			out := make(chan string, 1)
			in := io.NopCloser(strings.NewReader(tc.input))
			go linewiseCopy(ctx, tc.prefix, out, in)
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

func TestLogs(t *testing.T) {
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
			ctx := context.Background()
			for range tc.sessionCount {
				eg.Go(func() error {
					return c.Logs(ctx, testNS, testDeploy, testPod, tc.follow, 10, &buf)
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
