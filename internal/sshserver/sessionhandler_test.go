package sshserver_test

import (
	"bytes"
	"crypto/ed25519"
	"log/slog"
	"os"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/anmitsu/go-shlex"
	"github.com/gliderlabs/ssh"
	"github.com/uselagoon/ssh-portal/internal/sshserver"
	"go.uber.org/mock/gomock"
	gossh "golang.org/x/crypto/ssh"
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
			sshSession.EXPECT().Context().Return(sshContext).Times(2)
			sshContext.EXPECT().SessionID().Return("test_session_id")
			sshSession.EXPECT().RawCommand().Return(tc.rawCommand).Times(2)
			// emulate ssh.Session.Command()
			command, _ := shlex.Split(tc.rawCommand, true)
			sshSession.EXPECT().Command().Return(command).Times(3)
			sshSession.EXPECT().Subsystem().Return("")
			sshSession.EXPECT().User().Return(user).Times(3)
			k8sService.EXPECT().FindDeployment(
				sshContext,
				user,
				deployment,
			).Return(deployment, nil)
			// emulate the auth handler and marshal the details
			sshPermissions := ssh.Permissions{Permissions: &gossh.Permissions{}}
			sshContext.EXPECT().Permissions().Return(&sshPermissions).Times(5)
			sshserver.PermissionsMarshal(sshContext, 1, 2, "foo", "bar")
			// set up public key mock
			publicKey, _, err := ed25519.GenerateKey(nil)
			if err != nil {
				tt.Fatal(err)
			}
			sshPublicKey, err := gossh.NewPublicKey(publicKey)
			if err != nil {
				tt.Fatal(err)
			}
			sshSession.EXPECT().PublicKey().Return(sshPublicKey)
			// configure remaining mocks
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

func TestLagoonContainerLogs(t *testing.T) {
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
		"nginx logs administratively disabled": {
			user:             "project-test",
			deployment:       "nginx",
			rawCommand:       "service=nginx logs=tailLines=10",
			sftp:             false,
			logAccessEnabled: false,
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
			// configure common mocks
			sshSession.EXPECT().Context().Return(sshContext).Times(2)
			sshSession.EXPECT().RawCommand().Return(tc.rawCommand)
			sshSession.EXPECT().Subsystem().Return("")
			sshContext.EXPECT().Value(gomock.Any()).Return(nil).AnyTimes()
			sshContext.EXPECT().Done().Return(make(<-chan struct{})).AnyTimes()
			// emulate ssh.Session.Command()
			command, _ := shlex.Split(tc.rawCommand, true)
			// set up test buffer
			var buf bytes.Buffer
			if tc.logAccessEnabled {
				// configure logs enabled mocks
				k8sService.EXPECT().FindDeployment(
					sshContext,
					tc.user,
					tc.deployment,
				).Return(tc.deployment, nil)
				sshSession.EXPECT().Command().Return(command).Times(3)
				// emulate the auth handler and marshal permission details
				sshPermissions := ssh.Permissions{Permissions: &gossh.Permissions{}}
				sshContext.EXPECT().Permissions().Return(&sshPermissions).Times(5)
				sshserver.PermissionsMarshal(sshContext, 1, 2, "foo", "bar")
				// set up mocks for logs enabled
				sshContext.EXPECT().SessionID().Return("test_session_id")
				sshSession.EXPECT().User().Return(tc.user).Times(3)
				// set up public key mock
				publicKey, _, err := ed25519.GenerateKey(nil)
				if err != nil {
					tt.Fatal(err)
				}
				sshPublicKey, err := gossh.NewPublicKey(publicKey)
				if err != nil {
					tt.Fatal(err)
				}
				sshSession.EXPECT().PublicKey().Return(sshPublicKey)
				k8sService.EXPECT().LagoonContainerLogs(
					gomock.Any(), // private childCtx
					tc.user,
					tc.deployment,
					"",
					tc.follow,
					tc.taillines,
					sshSession,
				).Return(nil)
			} else {
				// configure logs disabled mocks
				sshSession.EXPECT().Command().Return(command).Times(2)
				sshContext.EXPECT().SessionID().Return("test_session_id").Times(2)
				sshSession.EXPECT().Exit(253).Return(nil)
				sshSession.EXPECT().Stderr().Return(&buf)
			}
			// execute callback
			callback(sshSession)
			// check assertions
			if !tc.logAccessEnabled {
				assert.Equal(
					tt,
					"log access is not enabled. SID: test_session_id\r\n",
					buf.String(),
					name)
			}
		})
	}
}

func TestLagoonSystemLogs(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	var testCases = map[string]struct {
		user             string
		jobType          string
		rawCommand       string
		sftp             bool
		logAccessEnabled bool
		pty              bool
		follow           bool
		taillines        int64
	}{
		"build logs": {
			user:             "project-test",
			jobType:          "build",
			rawCommand:       "lagoonSystem=build logs=tailLines=10",
			sftp:             false,
			logAccessEnabled: true,
			pty:              false,
			follow:           false,
			taillines:        10,
		},
		"task logs": {
			user:             "project-test",
			jobType:          "task",
			rawCommand:       "lagoonSystem=task logs=tailLines=10",
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
			// configure common mocks
			sshSession.EXPECT().Context().Return(sshContext).Times(2)
			sshSession.EXPECT().RawCommand().Return(tc.rawCommand)
			sshSession.EXPECT().Subsystem().Return("")
			sshContext.EXPECT().Value(gomock.Any()).Return(nil).AnyTimes()
			sshContext.EXPECT().Done().Return(make(<-chan struct{})).AnyTimes()
			// emulate ssh.Session.Command()
			command, _ := shlex.Split(tc.rawCommand, true)
			// set up test buffer
			var buf bytes.Buffer
			if tc.logAccessEnabled {
				sshSession.EXPECT().Command().Return(command).Times(3)
				// emulate the auth handler and marshal permission details
				sshPermissions := ssh.Permissions{Permissions: &gossh.Permissions{}}
				sshContext.EXPECT().Permissions().Return(&sshPermissions).Times(5)
				sshserver.PermissionsMarshal(sshContext, 1, 2, "foo", "bar")
				// set up mocks for logs enabled
				sshContext.EXPECT().SessionID().Return("test_session_id")
				sshSession.EXPECT().User().Return(tc.user).Times(2)
				// set up public key mock
				publicKey, _, err := ed25519.GenerateKey(nil)
				if err != nil {
					tt.Fatal(err)
				}
				sshPublicKey, err := gossh.NewPublicKey(publicKey)
				if err != nil {
					tt.Fatal(err)
				}
				sshSession.EXPECT().PublicKey().Return(sshPublicKey)
				k8sService.EXPECT().LagoonSystemLogs(
					gomock.Any(), // private childCtx
					tc.user,
					tc.jobType,
					"",
					tc.follow,
					tc.taillines,
					sshSession,
				).Return(nil)
			} else {
				// configure logs disabled mocks
				sshSession.EXPECT().Command().Return(command).Times(2)
				sshContext.EXPECT().SessionID().Return("test_session_id").Times(2)
				sshSession.EXPECT().Exit(253).Return(nil)
				sshSession.EXPECT().Stderr().Return(&buf)
			}
			// execute callback
			callback(sshSession)
			// check assertions
			if !tc.logAccessEnabled {
				assert.Equal(
					tt,
					"log access is not enabled. SID: test_session_id\r\n",
					buf.String(),
					name)
			}
		})
	}
}
