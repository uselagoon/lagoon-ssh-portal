package k8s

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUnidleReplicas(t *testing.T) {
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
					Annotations: map[string]string{idleAnnotation: tc.input},
				},
			}
			assert.Equal(tt, tc.expect, unidleReplicas(deploy), name)
		})
	}
}
