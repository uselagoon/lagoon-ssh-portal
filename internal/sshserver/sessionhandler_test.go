package sshserver_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/gliderlabs/ssh"
	"github.com/uselagoon/ssh-portal/internal/sshserver"
	"go.uber.org/mock/gomock"
)

func TestExec(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	var testCases = map[string]struct {
		user             string
		deployment       string
		rawCommand       []string
		command          []string
		sftp             bool
		logAccessEnabled bool
		pty              bool
	}{
		"bare interactive shell": {
			user:             "project-test",
			deployment:       "cli",
			rawCommand:       nil,
			command:          []string{"sh"},
			sftp:             false,
			logAccessEnabled: false,
			pty:              true,
		},
		"non-interactive id command": {
			user:             "project-test",
			deployment:       "cli",
			rawCommand:       []string{"id"},
			command:          []string{"sh", "-c", "id"},
			sftp:             false,
			logAccessEnabled: false,
			pty:              false,
		},
		"subshell": {
			user:             "project-test",
			deployment:       "cli",
			rawCommand:       []string{"/bin/sh", "-c", "( echo foo; echo bar; echo baz ) | tail -n2"},
			command:          []string{"sh", "-c", "/bin/sh -c '( echo foo; echo bar; echo baz ) | tail -n2'"},
			sftp:             false,
			logAccessEnabled: false,
			pty:              false,
		},
		"process substitution 1": {
			user:             "project-test",
			deployment:       "cli",
			rawCommand:       []string{"/bin/sh", "-c", "sleep 3 & echo $(pgrep sleep)"},
			command:          []string{"sh", "-c", "/bin/sh -c 'sleep 3 & echo $(pgrep sleep)'"},
			sftp:             false,
			logAccessEnabled: false,
			pty:              false,
		},
		"process substitution 2": {
			user:             "project-test",
			deployment:       "cli",
			rawCommand:       []string{"/bin/sh", "-c", "sleep 3 & echo $( pgrep sleep )"},
			command:          []string{"sh", "-c", "/bin/sh -c 'sleep 3 & echo $( pgrep sleep )'"},
			sftp:             false,
			logAccessEnabled: false,
			pty:              false,
		},
		"shell variables": {
			user:             "project-test",
			deployment:       "cli",
			rawCommand:       []string{"/bin/sh", "-c", "echo $$ $USER"},
			command:          []string{"sh", "-c", "/bin/sh -c 'echo $$ $USER'"},
			sftp:             false,
			logAccessEnabled: false,
			pty:              false,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			// set up mocks
			ctrl := gomock.NewController(tt)
			k8sService := NewMockK8SAPIService(ctrl)
			sshSession := NewMockSession(ctrl)
			sshContext := NewMockContext(ctrl)
			// configure callback
			callback := sshserver.SessionHandler(
				log,
				k8sService,
				tc.sftp,
				tc.logAccessEnabled,
			)
			// configure mocks
			sshSession.EXPECT().Context().Return(sshContext)
			sshContext.EXPECT().SessionID().Return("test_session_id")
			sshSession.EXPECT().Command().Return(tc.rawCommand).AnyTimes()
			sshSession.EXPECT().Subsystem().Return("")
			sshSession.EXPECT().User().Return(tc.user).AnyTimes()
			k8sService.EXPECT().FindDeployment(
				sshContext,
				tc.user,
				tc.deployment,
			).Return(tc.deployment, nil)
			sshContext.EXPECT().Value(sshserver.EnvironmentIDKey).Return(0)
			sshContext.EXPECT().Value(sshserver.EnvironmentNameKey).Return("test")
			sshContext.EXPECT().Value(sshserver.ProjectIDKey).Return(0)
			sshContext.EXPECT().Value(sshserver.ProjectNameKey).Return("project")
			sshContext.EXPECT().Value(sshserver.SSHFingerprint).Return("fingerprint")
			winch := make(<-chan ssh.Window)
			sshSession.EXPECT().Pty().Return(ssh.Pty{}, winch, tc.pty)
			sshSession.EXPECT().Stderr().Return(os.Stderr)
			k8sService.EXPECT().Exec(
				sshContext,
				tc.user,
				tc.deployment,
				"",
				tc.command,
				sshSession,
				os.Stderr,
				tc.pty,
				winch,
			).Return(nil)
			// execute callback
			callback(sshSession)
		})
	}
}

func TestLogs(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	var testCases = map[string]struct {
		user             string
		deployment       string
		rawCommand       []string
		command          []string
		sftp             bool
		logAccessEnabled bool
		pty              bool
		follow           bool
		taillines        int64
	}{
		"nginx logs": {
			user:             "project-test",
			deployment:       "nginx",
			rawCommand:       []string{"service=nginx", "logs=tailLines=10"},
			command:          nil,
			sftp:             false,
			logAccessEnabled: true,
			pty:              false,
			follow:           false,
			taillines:        10,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			// set up mocks
			ctrl := gomock.NewController(tt)
			k8sService := NewMockK8SAPIService(ctrl)
			sshSession := NewMockSession(ctrl)
			sshContext := NewMockContext(ctrl)
			// configure callback
			callback := sshserver.SessionHandler(
				log,
				k8sService,
				tc.sftp,
				tc.logAccessEnabled,
			)
			// configure mocks
			sshSession.EXPECT().Context().Return(sshContext)
			sshContext.EXPECT().SessionID().Return("test_session_id")
			sshSession.EXPECT().Command().Return(tc.rawCommand).AnyTimes()
			sshSession.EXPECT().Subsystem().Return("")
			sshSession.EXPECT().User().Return(tc.user).AnyTimes()
			k8sService.EXPECT().FindDeployment(
				sshContext,
				tc.user,
				tc.deployment,
			).Return(tc.deployment, nil)
			sshContext.EXPECT().Value(sshserver.EnvironmentIDKey).Return(0)
			sshContext.EXPECT().Value(sshserver.EnvironmentNameKey).Return("test")
			sshContext.EXPECT().Value(sshserver.ProjectIDKey).Return(0)
			sshContext.EXPECT().Value(sshserver.ProjectNameKey).Return("project")
			sshContext.EXPECT().Value(sshserver.SSHFingerprint).Return("fingerprint")

			// called by context.WithCancel()
			sshContext.EXPECT().Value(gomock.Any()).Return(nil).AnyTimes()

			sshContext.EXPECT().Done().Return(make(<-chan struct{})).AnyTimes()
			k8sService.EXPECT().Logs(
				gomock.Any(), // private childCtx
				tc.user,
				tc.deployment,
				"",
				tc.follow,
				tc.taillines,
				sshSession,
			).Return(nil)
			// execute callback
			callback(sshSession)
		})
	}
}
