package sshserver_test

import (
	"reflect"
	"testing"

	"github.com/uselagoon/ssh-portal/internal/sshserver"
)

type parsedParams struct {
	service   string
	container string
	args      []string
}

func TestParseConnectionParams(t *testing.T) {
	var testCases = map[string]struct {
		input  []string
		expect parsedParams
	}{
		"no special args": {
			input: []string{"drush", "do", "something"},
			expect: parsedParams{
				service:   "cli",
				container: "",
				args:      []string{"drush", "do", "something"},
			},
		},
		"service arg": {
			input: []string{"service=mongo", "drush", "do", "something"},
			expect: parsedParams{
				service:   "mongo",
				container: "",
				args:      []string{"drush", "do", "something"},
			},
		},
		"service and container args": {
			input: []string{"service=nginx", "container=php", "drush", "do", "something"},
			expect: parsedParams{
				service:   "nginx",
				container: "php",
				args:      []string{"drush", "do", "something"},
			},
		},
		"invalid order": {
			input: []string{"container=php", "service=nginx", "drush", "do", "something"},
			expect: parsedParams{
				service:   "cli",
				container: "",
				args:      []string{"container=php", "service=nginx", "drush", "do", "something"},
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			service, container, args := sshserver.ParseConnectionParams(tc.input)
			if tc.expect.service != service {
				tt.Fatalf("service: expected %v, got %v", tc.expect.service, service)
			}
			if tc.expect.container != container {
				tt.Fatalf("container: expected %v, got %v", tc.expect.container, container)
			}
			if !reflect.DeepEqual(tc.expect.args, args) {
				tt.Fatalf("args: expected %v, got %v", tc.expect.args, args)
			}
		})
	}
}
