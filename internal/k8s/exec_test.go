package k8s

import (
	"context"
	"testing"

	"github.com/alecthomas/assert/v2"
	appsv1 "k8s.io/api/apps/v1"
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
			deploys, err := c.idledDeploys(context.Background(), testNS)
			assert.NoError(tt, err, name)
			assert.Equal(tt, tc.expect, deployNames(deploys), name)
		})
	}
}
