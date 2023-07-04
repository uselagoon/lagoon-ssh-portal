package sshserver_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/uselagoon/ssh-portal/internal/sshserver"
)

type parsedParams struct {
	service   string
	container string
	logs      string
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
				logs:      "",
				args:      []string{"drush", "do", "something"},
			},
		},
		"service params": {
			input: []string{"service=mongo", "drush", "do", "something"},
			expect: parsedParams{
				service:   "mongo",
				container: "",
				logs:      "",
				args:      []string{"drush", "do", "something"},
			},
		},
		"service and container params": {
			input: []string{"service=nginx", "container=php", "drush", "do", "something"},
			expect: parsedParams{
				service:   "nginx",
				container: "php",
				logs:      "",
				args:      []string{"drush", "do", "something"},
			},
		},
		"invalid order": {
			input: []string{"container=php", "service=nginx", "drush", "do", "something"},
			expect: parsedParams{
				service:   "cli",
				container: "",
				logs:      "",
				args:      []string{"container=php", "service=nginx", "drush", "do", "something"},
			},
		},
		"service and logs params": {
			input: []string{"service=nginx", "logs=follow", "drush do something"},
			expect: parsedParams{
				service:   "nginx",
				container: "",
				logs:      "follow",
				args:      []string{"drush do something"},
			},
		},
		"service, container and logs params": {
			input: []string{"service=nginx", "container=php", "logs=follow", "drush do something"},
			expect: parsedParams{
				service:   "nginx",
				container: "php",
				logs:      "follow",
				args:      []string{"drush do something"},
			},
		},
		"service, container and logs params (wrong order)": {
			input: []string{"service=nginx", "logs=follow", "container=php", "drush do something"},
			expect: parsedParams{
				service:   "nginx",
				container: "",
				logs:      "follow",
				args:      []string{"container=php", "drush do something"},
			},
		},
		"service and logs params (invalid logs value)": {
			input: []string{"service=nginx", "logs=php", "drush", "do", "something"},
			expect: parsedParams{
				service:   "nginx",
				container: "",
				logs:      "php",
				args:      []string{"drush", "do", "something"},
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			service, container, logs, args := sshserver.ParseConnectionParams(tc.input)
			if tc.expect.service != service {
				tt.Fatalf("service: expected %v, got %v", tc.expect.service, service)
			}
			if tc.expect.container != container {
				tt.Fatalf("container: expected %v, got %v", tc.expect.container, container)
			}
			if tc.expect.logs != logs {
				tt.Fatalf("logs: expected %v, got %v", tc.expect.logs, logs)
			}
			if !reflect.DeepEqual(tc.expect.args, args) {
				tt.Fatalf("args: expected %v, got %v", tc.expect.args, args)
			}
		})
	}
}

func TestValidateConnectionParams(t *testing.T) {
	type result struct {
		follow    bool
		tailLines int64
		err       error
	}
	var testCases = map[string]struct {
		input  parsedParams
		expect result
	}{
		"follow": {
			input: parsedParams{
				service: "nginx-php",
				logs:    "follow",
			},
			expect: result{
				follow: true,
			},
		},
		"tail": {
			input: parsedParams{
				service: "nginx-php",
				logs:    "tailLines=201",
			},
			expect: result{
				tailLines: 201,
			},
		},
		"follow and tail": {
			input: parsedParams{
				service: "nginx-php",
				logs:    "follow,tailLines=10",
			},
			expect: result{
				follow:    true,
				tailLines: 10,
			},
		},
		"tail and follow": {
			input: parsedParams{
				service: "nginx-php",
				logs:    "tailLines=100,follow",
			},
			expect: result{
				follow:    true,
				tailLines: 100,
			},
		},
		"multiple tail and follow": {
			input: parsedParams{
				service: "nginx-php",
				logs:    "tailLines=100,follow,tailLines=11",
			},
			expect: result{
				follow:    true,
				tailLines: 11,
			},
		},
		"invalid tail value": {
			input: parsedParams{
				service: "nginx-php",
				logs:    "tailLines=10f",
			},
			expect: result{
				err: sshserver.ErrInvalidLogsValue,
			},
		},
		"garbage prefix in logs arg": {
			input: parsedParams{
				service: "nginx-php",
				logs:    "fallow,tailLines=10",
			},
			expect: result{
				err: sshserver.ErrInvalidLogsValue,
			},
		},
		"garbage infix in logs arg": {
			input: parsedParams{
				service: "nginx-php",
				logs:    "follow,nofollow,tailLines=10f",
			},
			expect: result{
				err: sshserver.ErrInvalidLogsValue,
			},
		},
		"garbage suffix in logs arg": {
			input: parsedParams{
				service: "nginx-php",
				logs:    "follow,tailLines=10,nofollow",
			},
			expect: result{
				err: sshserver.ErrInvalidLogsValue,
			},
		},
		"arguments after logs and invalid logs value": {
			input: parsedParams{
				service: "cli",
				logs:    "php",
				args:    []string{"drush", "do", "something"},
			},
			expect: result{
				err: sshserver.ErrCmdArgsAfterLogs,
			},
		},
		"invalid logs value": {
			input: parsedParams{
				service: "cli",
				logs:    "php",
			},
			expect: result{
				err: sshserver.ErrInvalidLogsValue,
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			follow, tailLines, err := sshserver.ParseLogsArg(
				tc.input.service, tc.input.logs, tc.input.args)
			if !errors.Is(err, tc.expect.err) {
				tt.Fatalf("expected %v, got %v", tc.expect.err, err)
			}
			if follow != tc.expect.follow {
				tt.Fatalf("expected %v, got %v", tc.expect.follow, follow)
			}
			if tailLines != tc.expect.tailLines {
				tt.Fatalf("expected %v, got %v", tc.expect.tailLines, tailLines)
			}
		})
	}
}
