package sshserver_test

import (
	"crypto/ed25519"
	"log/slog"
	"os"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/gliderlabs/ssh"
	"github.com/uselagoon/ssh-portal/internal/sshserver"
	gomock "go.uber.org/mock/gomock"
	gossh "golang.org/x/crypto/ssh"
)

func TestPubKeyHandler(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	var testCases = map[string]struct {
		keyCanAccessEnv bool
	}{
		"access granted": {
			keyCanAccessEnv: true,
		},
		"access denied": {
			keyCanAccessEnv: false,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			k8sService := NewMockK8SAPIService(ctrl)
			natsService := NewMockNATSService(ctrl)
			sshContext := NewMockContext(ctrl)
			// configure callback
			callback := sshserver.PubKeyHandler(
				log,
				natsService,
				k8sService,
			)
			// configure mocks
			namespaceName := "my-project-master"
			sessionID := "abc123"
			projectID := 1
			environmentID := 2
			sshContext.EXPECT().User().Return(namespaceName).AnyTimes()
			sshContext.EXPECT().SessionID().Return(sessionID).AnyTimes()
			k8sService.EXPECT().NamespaceDetails(sshContext, namespaceName).
				Return(environmentID, projectID, "master", "my-project", nil)
			// set up public key mock
			publicKey, _, err := ed25519.GenerateKey(nil)
			if err != nil {
				tt.Fatal(err)
			}
			sshPublicKey, err := gossh.NewPublicKey(publicKey)
			if err != nil {
				tt.Fatal(err)
			}
			fingerprint := gossh.FingerprintSHA256(sshPublicKey)
			natsService.EXPECT().KeyCanAccessEnvironment(
				sessionID,
				fingerprint,
				namespaceName,
				projectID,
				environmentID,
			).Return(tc.keyCanAccessEnv, nil)
			// set up permissions mock
			sshPermissions := ssh.Permissions{Permissions: &gossh.Permissions{}}
			// permissions are not touched if access is denied
			if tc.keyCanAccessEnv {
				sshContext.EXPECT().Permissions().Return(&sshPermissions)
			}
			// execute callback
			assert.Equal(
				tt, tc.keyCanAccessEnv, callback(sshContext, sshPublicKey), name)
		})
	}
}
