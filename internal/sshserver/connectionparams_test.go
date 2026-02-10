package sshserver_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/anmitsu/go-shlex"
	"github.com/uselagoon/ssh-portal/internal/lagoon"
	"github.com/uselagoon/ssh-portal/internal/sshserver"
)

type parsedParams struct {
	service      string
	container    string
	logs         string
	rawCmd       string
	follow       bool
	tailLines    int64
	err          error
	lagoonSystem lagoon.SystemLogsType
	name         string
}

var execTestCases = map[string]struct {
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
			rawCmd:    "drush do something",
		},
	},
	"service param no args": {
		rawCmd: "service=mysvc",
		cmd:    []string{"service=mysvc"},
		expect: parsedParams{
			service:   "mysvc",
			container: "",
			rawCmd:    "",
		},
	},
	"service param single arg": {
		rawCmd: "service=mysvc id",
		cmd:    []string{"service=mysvc", "id"},
		expect: parsedParams{
			service:   "mysvc",
			container: "",
			rawCmd:    "id",
		},
	},
	"service param and multiple args": {
		rawCmd: "service=mongo drush do something",
		cmd:    []string{"service=mongo", "drush", "do", "something"},
		expect: parsedParams{
			service:   "mongo",
			container: "",
			rawCmd:    "drush do something",
		},
	},
	"service and container params": {
		rawCmd: "service=nginx container=php drush do something",
		cmd:    []string{"service=nginx", "container=php", "drush", "do", "something"},
		expect: parsedParams{
			service:   "nginx",
			container: "php",
			rawCmd:    "drush do something",
		},
	},
	"invalid order": {
		rawCmd: "container=php service=nginx drush do something",
		cmd:    []string{"container=php", "service=nginx", "drush", "do", "something"},
		expect: parsedParams{
			service:   "cli",
			container: "",
			rawCmd:    "container=php service=nginx drush do something",
		},
	},
	"service and logs params": {
		rawCmd: "service=nginx logs=follow drush do something",
		cmd:    []string{"service=nginx", "logs=follow", "drush", "do", "something"},
		expect: parsedParams{
			service:   "nginx",
			container: "",
			rawCmd:    "logs=follow drush do something",
		},
	},
	"service, container and logs params": {
		rawCmd: "service=nginx container=php logs=follow drush do something",
		cmd:    []string{"service=nginx", "container=php", "logs=follow", "drush", "do", "something"},
		expect: parsedParams{
			service:   "nginx",
			container: "php",
			rawCmd:    "logs=follow drush do something",
		},
	},
	"service, container and logs params (wrong order)": {
		rawCmd: "service=nginx logs=follow container=php drush do something",
		cmd:    []string{"service=nginx", "logs=follow", "container=php", "drush", "do", "something"},
		expect: parsedParams{
			service:   "nginx",
			container: "",
			rawCmd:    "logs=follow container=php drush do something",
		},
	},
	"service and logs params (invalid logs value)": {
		rawCmd: "service=nginx logs=php drush do something",
		cmd:    []string{"service=nginx", "logs=php", "drush", "do", "something"},
		expect: parsedParams{
			service:   "nginx",
			container: "",
			rawCmd:    "logs=php drush do something",
		},
	},
	"subshell misquoted": {
		rawCmd: "/bin/sh -c ( echo foo; echo bar; echo baz ) | tail -n2",
		cmd:    []string{"/bin/sh", "-c", "(", "echo", "foo;", "echo", "bar;", "echo", "baz", ")", "|", "tail", "-n2"},
		expect: parsedParams{
			service:   "cli",
			container: "",
			rawCmd:    "/bin/sh -c ( echo foo; echo bar; echo baz ) | tail -n2",
		},
	},
	"subshell quoted": {
		rawCmd: `/bin/sh -c "( echo foo; echo bar; echo baz ) | tail -n2"`,
		cmd:    []string{"/bin/sh", "-c", "( echo foo; echo bar; echo baz ) | tail -n2"},
		expect: parsedParams{
			service:   "cli",
			container: "",
			rawCmd:    `/bin/sh -c "( echo foo; echo bar; echo baz ) | tail -n2"`,
		},
	},
	"process substitution misquoted": {
		rawCmd: `/bin/sh -c sleep 3 & sleep 1 && pgrep sleep`,
		cmd:    []string{"/bin/sh", "-c", "sleep", "3", "&", "sleep", "1", "&&", "pgrep", "sleep"},
		expect: parsedParams{
			service:   "cli",
			container: "",
			rawCmd:    `/bin/sh -c sleep 3 & sleep 1 && pgrep sleep`,
		},
	},
	"process substitution quoted": {
		rawCmd: `/bin/sh -c "sleep 3 & sleep 1 && pgrep sleep"`,
		cmd:    []string{"/bin/sh", "-c", "sleep 3 & sleep 1 && pgrep sleep"},
		expect: parsedParams{
			service:   "cli",
			container: "",
			rawCmd:    `/bin/sh -c "sleep 3 & sleep 1 && pgrep sleep"`,
		},
	},
	"shell variables misquoted": {
		rawCmd: "/bin/sh -c echo $$ $USER",
		cmd:    []string{"/bin/sh", "-c", "echo", "$$", "$USER"},
		expect: parsedParams{
			service:   "cli",
			container: "",
			rawCmd:    "/bin/sh -c echo $$ $USER",
		},
	},
	"shell variables quoted": {
		rawCmd: "/bin/sh -c 'echo $$ $USER'",
		cmd:    []string{"/bin/sh", "-c", "echo $$ $USER"},
		expect: parsedParams{
			service:   "cli",
			container: "",
			rawCmd:    "/bin/sh -c 'echo $$ $USER'",
		},
	},
	"shell variables and service": {
		rawCmd: `service=foo echo "$(( $$ + 1 ))"`,
		cmd:    []string{"service=foo", "echo", "$(( $$ + 1 ))"},
		expect: parsedParams{
			service:   "foo",
			container: "",
			rawCmd:    `echo "$(( $$ + 1 ))"`,
		},
	},
	"ansible": {
		rawCmd: "/bin/sh -c '( umask 77 && mkdir -p \"` echo /tmp `\"&& mkdir \"` echo /tmp/ansible-tmp-1729564333.3484864-620266-10397749948780 `\" && echo ansible-tmp-1729564333.3484864-620266-10397749948780=\"` echo /tmp/ansible-tmp-1729564333.3484864-620266-10397749948780 `\" ) && sleep 0'",
		cmd:    []string{"/bin/sh", "-c", "( umask 77 && mkdir -p \"` echo /tmp `\"&& mkdir \"` echo /tmp/ansible-tmp-1729564333.3484864-620266-10397749948780 `\" && echo ansible-tmp-1729564333.3484864-620266-10397749948780=\"` echo /tmp/ansible-tmp-1729564333.3484864-620266-10397749948780 `\" ) && sleep 0"},
		expect: parsedParams{
			service:   "cli",
			container: "",
			rawCmd:    "/bin/sh -c '( umask 77 && mkdir -p \"` echo /tmp `\"&& mkdir \"` echo /tmp/ansible-tmp-1729564333.3484864-620266-10397749948780 `\" && echo ansible-tmp-1729564333.3484864-620266-10397749948780=\"` echo /tmp/ansible-tmp-1729564333.3484864-620266-10397749948780 `\" ) && sleep 0'",
		},
	},
	"service and lagoonSystem params": {
		rawCmd: "service=nginx lagoonSystem=build drush do something",
		cmd:    []string{"service=nginx", "lagoonSystem=build", "drush", "do", "something"},
		expect: parsedParams{
			service:   "nginx",
			container: "",
			rawCmd:    "lagoonSystem=build drush do something",
		},
	},
}

func TestParseExecSessionParams(t *testing.T) {
	for name, tc := range execTestCases {
		t.Run(name, func(tt *testing.T) {
			service, container, rawCmd, err :=
				sshserver.ParseExecSessionParams(tc.cmd, tc.rawCmd)
			assert.NoError(tt, err, name)
			assert.Equal(tt, tc.expect.service, service, name)
			assert.Equal(tt, tc.expect.container, container, name)
			assert.Equal(tt, tc.expect.rawCmd, rawCmd, name)
		})
	}
}

var containerLogsTestCases = map[string]struct {
	cmd    []string
	expect parsedParams
}{
	"nginx follow": {
		cmd: []string{"service=nginx", "logs=follow"},
		expect: parsedParams{
			service: "nginx",
			logs:    "follow",
			follow:  true,
		},
	},
	"nginx tailLines": {
		cmd: []string{"service=nginx", "logs=tailLines=123"},
		expect: parsedParams{
			service:   "nginx",
			logs:      "tailLines=123",
			tailLines: 123,
		},
	},
	"nginx follow tailLines": {
		cmd: []string{"service=nginx", "logs=follow,tailLines=123"},
		expect: parsedParams{
			service:   "nginx",
			logs:      "follow,tailLines=123",
			follow:    true,
			tailLines: 123,
		},
	},
	"mongo tailLines follow": {
		cmd: []string{"service=mongo", "logs=tailLines=123,follow"},
		expect: parsedParams{
			service:   "mongo",
			logs:      "tailLines=123,follow",
			follow:    true,
			tailLines: 123,
		},
	},
	"nginx php follow tailLines": {
		cmd: []string{"service=nginx", "container=php", "logs=follow,tailLines=123"},
		expect: parsedParams{
			service:   "nginx",
			container: "php",
			logs:      "follow,tailLines=123",
			follow:    true,
			tailLines: 123,
		},
	},
	"repeated args": {
		cmd: []string{"service=mongo", "logs=tailLines=123,follow,tailLines=234"},
		expect: parsedParams{
			service:   "mongo",
			logs:      "tailLines=123,follow,tailLines=234",
			follow:    true,
			tailLines: 234,
		},
	},
	"repeated args again": {
		cmd: []string{"service=mongo", "logs=tailLines=123,tailLines=234,follow"},
		expect: parsedParams{
			service:   "mongo",
			logs:      "tailLines=123,tailLines=234,follow",
			follow:    true,
			tailLines: 234,
		},
	},
	"invalid logs value": {
		cmd: []string{"service=mongo", "logs=foo"},
		expect: parsedParams{
			service: "mongo",
			logs:    "foo",
			err:     sshserver.ErrInvalidLogsValue,
		},
	},
	"garbage infix in logs value": {
		cmd: []string{"service=mongo", "logs=follow,nofollow,tailLines=10"},
		expect: parsedParams{
			service: "mongo",
			logs:    "follow,nofollow,tailLines=10",
			err:     sshserver.ErrInvalidLogsValue,
		},
	},
	"garbage suffix in logs value": {
		cmd: []string{"service=mongo", "logs=follow,tailLines=10,nofollow"},
		expect: parsedParams{
			service: "mongo",
			logs:    "follow,tailLines=10,nofollow",
			err:     sshserver.ErrInvalidLogsValue,
		},
	},
	"one invalid logs value": {
		cmd: []string{"service=mongo", "logs=fallow,tailLines=10"},
		expect: parsedParams{
			service: "mongo",
			logs:    "fallow,tailLines=10",
			err:     sshserver.ErrInvalidLogsValue,
		},
	},
	"invalid logs value again": {
		cmd: []string{"service=mongo", "logs=follow,blah"},
		expect: parsedParams{
			service: "mongo",
			logs:    "follow,blah",
			err:     sshserver.ErrInvalidLogsValue,
		},
	},
	"invalid tailLines value": {
		cmd: []string{"service=mongo", "logs=follow,tailLines=abc"},
		expect: parsedParams{
			service: "mongo",
			logs:    "follow,tailLines=abc",
			err:     sshserver.ErrInvalidLogsValue,
		},
	},
	"invalid tailLines value again": {
		cmd: []string{"service=mongo", "logs=follow,tailLines=10f"},
		expect: parsedParams{
			service: "mongo",
			logs:    "follow,tailLines=10f",
			err:     sshserver.ErrInvalidLogsValue,
		},
	},
	"invalid tailLines value float": {
		cmd: []string{"service=mongo", "logs=follow,tailLines=10.0"},
		expect: parsedParams{
			service: "mongo",
			logs:    "follow,tailLines=10.0",
			err:     sshserver.ErrInvalidLogsValue,
		},
	},
}

func TestParseLogs(t *testing.T) {
	for name, tc := range containerLogsTestCases {
		t.Run(name, func(tt *testing.T) {
			// test parseLogsSessionParams
			service, container, logs, err := sshserver.ParseContainerLogsSessionParams(tc.cmd)
			assert.NoError(tt, err, name)
			assert.Equal(tt, tc.expect.service, service, name)
			assert.Equal(tt, tc.expect.container, container, name)
			assert.Equal(tt, tc.expect.logs, logs, name)
			// test parseLogsArg
			follow, tailLines, err := sshserver.ParseLogsArg(logs)
			assert.Equal(tt, tc.expect.follow, follow, name)
			assert.Equal(tt, tc.expect.tailLines, tailLines, name)
			assert.Equal(tt, tc.expect.err, err, name)
		})
	}
}

var systemLogsTestCases = map[string]struct {
	cmd    []string
	expect parsedParams
}{
	"build logs follow": {
		cmd: []string{"lagoonSystem=build", "logs=follow"},
		expect: parsedParams{
			lagoonSystem: lagoon.Build,
			logs:         "follow",
			follow:       true,
		},
	},
	"build logs tailLines": {
		cmd: []string{"lagoonSystem=build", "logs=tailLines=33"},
		expect: parsedParams{
			lagoonSystem: lagoon.Build,
			logs:         "tailLines=33",
			tailLines:    33,
		},
	},
	"build logs follow,tailLines": {
		cmd: []string{"lagoonSystem=build", "logs=follow,tailLines=33"},
		expect: parsedParams{
			lagoonSystem: lagoon.Build,
			logs:         "follow,tailLines=33",
			tailLines:    33,
			follow:       true,
		},
	},
	"build logs tailLines,follow": {
		cmd: []string{"lagoonSystem=build", "logs=tailLines=33,follow"},
		expect: parsedParams{
			lagoonSystem: lagoon.Build,
			logs:         "tailLines=33,follow",
			tailLines:    33,
			follow:       true,
		},
	},
	"build logs tailLines twice": {
		cmd: []string{"lagoonSystem=build", "logs=tailLines=33,tailLines=22"},
		expect: parsedParams{
			lagoonSystem: lagoon.Build,
			logs:         "tailLines=33,tailLines=22",
			tailLines:    22,
		},
	},
	"build logs name tailLines": {
		cmd: []string{"lagoonSystem=build", "name=mybuild", "logs=tailLines=22"},
		expect: parsedParams{
			lagoonSystem: lagoon.Build,
			logs:         "tailLines=22",
			tailLines:    22,
			name:         "mybuild",
		},
	},
	"task logs name tailLines": {
		cmd: []string{"lagoonSystem=task", "name=mytask", "logs=tailLines=22"},
		expect: parsedParams{
			lagoonSystem: lagoon.Task,
			logs:         "tailLines=22",
			tailLines:    22,
			name:         "mytask",
		},
	},
}

func TestParseLagoonSystemLogsSessionParams(t *testing.T) {
	for name, tc := range systemLogsTestCases {
		t.Run(name, func(tt *testing.T) {
			lagoonSystem, lsName, logs, err :=
				sshserver.ParseSystemLogsSessionParams(tc.cmd)
			assert.NoError(tt, err, name)
			assert.Equal(tt, tc.expect.lagoonSystem, lagoonSystem, name)
			assert.Equal(tt, tc.expect.name, lsName, name)
			assert.Equal(tt, tc.expect.logs, logs, name)
			// test parseLogsArg
			follow, tailLines, err := sshserver.ParseLogsArg(logs)
			assert.Equal(tt, tc.expect.follow, follow, name)
			assert.Equal(tt, tc.expect.tailLines, tailLines, name)
			assert.Equal(tt, tc.expect.err, err, name)
		})
	}
}

func TestSessionType(t *testing.T) {
	for name, tc := range execTestCases {
		t.Run(name, func(tt *testing.T) {
			assert.Equal(
				tt, sshserver.ExecSession, sshserver.ParseSessionType(tc.cmd), name)
			// confirm the test data is correct: emulate ssh.Session.Command()
			cmd, err := shlex.Split(tc.rawCmd, true)
			assert.NoError(tt, err, name)
			assert.Equal(tt, tc.cmd, cmd, name)
		})
	}
	for name, tc := range containerLogsTestCases {
		t.Run(name, func(tt *testing.T) {
			assert.Equal(
				tt, sshserver.LagoonContainerLogsSession, sshserver.ParseSessionType(tc.cmd), name)
		})
	}
	for name, tc := range systemLogsTestCases {
		t.Run(name, func(tt *testing.T) {
			assert.Equal(
				tt, sshserver.LagoonSystemLogsSession, sshserver.ParseSessionType(tc.cmd), name)
		})
	}
}
