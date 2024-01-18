package sshserver_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/gliderlabs/ssh"
	"github.com/uselagoon/ssh-portal/internal/mock"
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
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			// set up mocks
			ctrl := gomock.NewController(tt)
			k8sService := mock.NewMockK8SAPIService(ctrl)
			sshSession := mock.NewMockSession(ctrl)
			sshContext := mock.NewMockContext(ctrl)
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
			sshContext.EXPECT().Value(sshserver.CtxKey(0)).Return(0)
			sshContext.EXPECT().Value(sshserver.CtxKey(1)).Return("test")
			sshContext.EXPECT().Value(sshserver.CtxKey(2)).Return(0)
			sshContext.EXPECT().Value(sshserver.CtxKey(3)).Return("project")
			sshContext.EXPECT().Value(sshserver.CtxKey(4)).Return("fingerprint")
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
