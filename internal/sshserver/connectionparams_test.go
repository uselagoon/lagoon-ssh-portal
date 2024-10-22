package sshserver_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/anmitsu/go-shlex"
	"github.com/uselagoon/ssh-portal/internal/sshserver"
)

type parsedParams struct {
	service   string
	container string
	logs      string
	rawCmd    string
}

func TestParseConnectionParams(t *testing.T) {
	var testCases = map[string]struct {
		rawCmd string
		cmd    []string
		expect parsedParams
	}{
		"no special args": {
			rawCmd: "drush do something",
			cmd:    []string{"drush", "do", "something"},
			expect: parsedParams{
				service:   "cli",
				container: "",
				logs:      "",
				rawCmd:    "drush do something",
			},
		},
		"service params": {
			rawCmd: "service=mongo drush do something",
			cmd:    []string{"service=mongo", "drush", "do", "something"},
			expect: parsedParams{
				service:   "mongo",
				container: "",
				logs:      "",
				rawCmd:    "drush do something",
			},
		},
		"service and container params": {
			rawCmd: "service=nginx container=php drush do something",
			cmd:    []string{"service=nginx", "container=php", "drush", "do", "something"},
			expect: parsedParams{
				service:   "nginx",
				container: "php",
				logs:      "",
				rawCmd:    "drush do something",
			},
		},
		"invalid order": {
			rawCmd: "container=php service=nginx drush do something",
			cmd:    []string{"container=php", "service=nginx", "drush", "do", "something"},
			expect: parsedParams{
				service:   "cli",
				container: "",
				logs:      "",
				rawCmd:    "container=php service=nginx drush do something",
			},
		},
		"service and logs params": {
			rawCmd: "service=nginx logs=follow drush do something",
			cmd:    []string{"service=nginx", "logs=follow", "drush", "do", "something"},
			expect: parsedParams{
				service:   "nginx",
				container: "",
				logs:      "follow",
				rawCmd:    "drush do something",
			},
		},
		"service, container and logs params": {
			rawCmd: "service=nginx container=php logs=follow drush do something",
			cmd:    []string{"service=nginx", "container=php", "logs=follow", "drush", "do", "something"},
			expect: parsedParams{
				service:   "nginx",
				container: "php",
				logs:      "follow",
				rawCmd:    "drush do something",
			},
		},
		"service, container and logs params (wrong order)": {
			rawCmd: "service=nginx logs=follow container=php drush do something",
			cmd:    []string{"service=nginx", "logs=follow", "container=php", "drush", "do", "something"},
			expect: parsedParams{
				service:   "nginx",
				container: "",
				logs:      "follow",
				rawCmd:    "container=php drush do something",
			},
		},
		"service and logs params (invalid logs value)": {
			rawCmd: "service=nginx logs=php drush do something",
			cmd:    []string{"service=nginx", "logs=php", "drush", "do", "something"},
			expect: parsedParams{
				service:   "nginx",
				container: "",
				logs:      "php",
				rawCmd:    "drush do something",
			},
		},
		"subshell misquoted": {
			rawCmd: "/bin/sh -c ( echo foo; echo bar; echo baz ) | tail -n2",
			cmd:    []string{"/bin/sh", "-c", "(", "echo", "foo;", "echo", "bar;", "echo", "baz", ")", "|", "tail", "-n2"},
			expect: parsedParams{
				service:   "cli",
				container: "",
				logs:      "",
				rawCmd:    "/bin/sh -c ( echo foo; echo bar; echo baz ) | tail -n2",
			},
		},
		"subshell quoted": {
			rawCmd: `/bin/sh -c "( echo foo; echo bar; echo baz ) | tail -n2"`,
			cmd:    []string{"/bin/sh", "-c", "( echo foo; echo bar; echo baz ) | tail -n2"},
			expect: parsedParams{
				service:   "cli",
				container: "",
				logs:      "",
				rawCmd:    `/bin/sh -c "( echo foo; echo bar; echo baz ) | tail -n2"`,
			},
		},
		"process substitution misquoted": {
			rawCmd: `/bin/sh -c sleep 3 & sleep 1 && pgrep sleep`,
			cmd:    []string{"/bin/sh", "-c", "sleep", "3", "&", "sleep", "1", "&&", "pgrep", "sleep"},
			expect: parsedParams{
				service:   "cli",
				container: "",
				logs:      "",
				rawCmd:    `/bin/sh -c sleep 3 & sleep 1 && pgrep sleep`,
			},
		},
		"process substitution quoted": {
			rawCmd: `/bin/sh -c "sleep 3 & sleep 1 && pgrep sleep"`,
			cmd:    []string{"/bin/sh", "-c", "sleep 3 & sleep 1 && pgrep sleep"},
			expect: parsedParams{
				service:   "cli",
				container: "",
				logs:      "",
				rawCmd:    `/bin/sh -c "sleep 3 & sleep 1 && pgrep sleep"`,
			},
		},
		"shell variables misquoted": {
			rawCmd: "/bin/sh -c echo $$ $USER",
			cmd:    []string{"/bin/sh", "-c", "echo", "$$", "$USER"},
			expect: parsedParams{
				service:   "cli",
				container: "",
				logs:      "",
				rawCmd:    "/bin/sh -c echo $$ $USER",
			},
		},
		"shell variables quoted": {
			rawCmd: "/bin/sh -c 'echo $$ $USER'",
			cmd:    []string{"/bin/sh", "-c", "echo $$ $USER"},
			expect: parsedParams{
				service:   "cli",
				container: "",
				logs:      "",
				rawCmd:    "/bin/sh -c 'echo $$ $USER'",
			},
		},
		"shell variables and service": {
			rawCmd: `service=foo echo "$(( $$ + 1 ))"`,
			cmd:    []string{"service=foo", "echo", "$(( $$ + 1 ))"},
			expect: parsedParams{
				service:   "foo",
				container: "",
				logs:      "",
				rawCmd:    `echo "$(( $$ + 1 ))"`,
			},
		},
		"ansible": {
			rawCmd: "/bin/sh -c '( umask 77 && mkdir -p \"` echo /tmp `\"&& mkdir \"` echo /tmp/ansible-tmp-1729564333.3484864-620266-10397749948780 `\" && echo ansible-tmp-1729564333.3484864-620266-10397749948780=\"` echo /tmp/ansible-tmp-1729564333.3484864-620266-10397749948780 `\" ) && sleep 0'",
			cmd:    []string{"/bin/sh", "-c", "( umask 77 && mkdir -p \"` echo /tmp `\"&& mkdir \"` echo /tmp/ansible-tmp-1729564333.3484864-620266-10397749948780 `\" && echo ansible-tmp-1729564333.3484864-620266-10397749948780=\"` echo /tmp/ansible-tmp-1729564333.3484864-620266-10397749948780 `\" ) && sleep 0"},
			expect: parsedParams{
				service:   "cli",
				container: "",
				logs:      "",
				rawCmd:    "/bin/sh -c '( umask 77 && mkdir -p \"` echo /tmp `\"&& mkdir \"` echo /tmp/ansible-tmp-1729564333.3484864-620266-10397749948780 `\" && echo ansible-tmp-1729564333.3484864-620266-10397749948780=\"` echo /tmp/ansible-tmp-1729564333.3484864-620266-10397749948780 `\" ) && sleep 0'",
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			service, container, logs, rawCmd := sshserver.ParseConnectionParams(tc.cmd, tc.rawCmd)
			assert.Equal(tt, tc.expect.service, service, name)
			assert.Equal(tt, tc.expect.container, container, name)
			assert.Equal(tt, tc.expect.logs, logs, name)
			assert.Equal(tt, tc.expect.rawCmd, rawCmd, name)
			// and just to confirm the test data is correct, emulate ssh.Session.Command()
			cmd, _ := shlex.Split(tc.rawCmd, true)
			assert.Equal(tt, tc.cmd, cmd, name)
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
				rawCmd:  "drush do something",
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
				tc.input.service, tc.input.logs, tc.input.rawCmd)
			assert.IsError(tt, err, tc.expect.err, name)
			assert.Equal(tt, tc.expect.follow, follow, name)
			assert.Equal(tt, tc.expect.tailLines, tailLines, name)
		})
	}
}
