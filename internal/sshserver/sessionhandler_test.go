package sshserver_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/anmitsu/go-shlex"
	"github.com/gliderlabs/ssh"
	"github.com/uselagoon/ssh-portal/internal/sshserver"
	"go.uber.org/mock/gomock"
)

func TestExec(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	var (
		user       = "project-test"
		deployment = "cli"
	)
	var testCases = map[string]struct {
		rawCommand       string
		command          []string
		sftp             bool
		logAccessEnabled bool
		pty              bool
	}{
		"bare interactive shell": {
			rawCommand:       "",
			command:          []string{"sh"},
			sftp:             false,
			logAccessEnabled: false,
			pty:              true,
		},
		"non-interactive id command": {
			rawCommand:       "id",
			command:          []string{"sh", "-c", "id"},
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
			sshSession.EXPECT().RawCommand().Return(tc.rawCommand).Times(2)
			// emulate ssh.Session.Command()
			command, _ := shlex.Split(tc.rawCommand, true)
			sshSession.EXPECT().Command().Return(command).Times(2)
			sshSession.EXPECT().Subsystem().Return("")
			sshSession.EXPECT().User().Return(user).Times(3)
			k8sService.EXPECT().FindDeployment(
				sshContext,
				user,
				deployment,
			).Return(deployment, nil)
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
				user,
				deployment,
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
		rawCommand       string
		sftp             bool
		logAccessEnabled bool
		pty              bool
		follow           bool
		taillines        int64
	}{
		"nginx logs": {
			user:             "project-test",
			deployment:       "nginx",
			rawCommand:       "service=nginx logs=tailLines=10",
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
			sshSession.EXPECT().RawCommand().Return(tc.rawCommand).Times(2)
			// emulate ssh.Session.Command()
			command, _ := shlex.Split(tc.rawCommand, true)
			sshSession.EXPECT().Command().Return(command).Times(2)
			sshSession.EXPECT().Subsystem().Return("")
			sshSession.EXPECT().User().Return(tc.user).Times(3)
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
