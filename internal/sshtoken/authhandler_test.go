package sshtoken_test

import (
	"crypto/ed25519"
	"log/slog"
	"os"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/sshtoken"
	gomock "go.uber.org/mock/gomock"
	gossh "golang.org/x/crypto/ssh"
)

func TestPubKeyHandler(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	var testCases = map[string]struct {
		userBySSHFingerprintErr error
		keyFound                bool
	}{
		"key matches user": {
			userBySSHFingerprintErr: nil,
			keyFound:                true,
		},
		"key doesn't match user": {
			userBySSHFingerprintErr: lagoondb.ErrNoResult,
			keyFound:                false,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			ctrl := gomock.NewController(tt)
			ldbService := NewMockLagoonDBService(ctrl)
			sshContext := NewMockContext(ctrl)
			// configure callback
			callback := sshtoken.PubKeyHandler(
				log,
				ldbService,
			)
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
			// configure mocks
			userUUID := uuid.Must(uuid.NewRandom())
			ldbService.EXPECT().UserBySSHFingerprint(sshContext, fingerprint).
				Return(&lagoondb.User{UUID: &userUUID}, tc.userBySSHFingerprintErr)
			sessionID := "abc123"
			sshContext.EXPECT().SessionID().Return(sessionID).AnyTimes()
			// set up permissions mock
			sshPermissions := ssh.Permissions{Permissions: &gossh.Permissions{}}
			if tc.keyFound {
				// permissions are not touched if access is denied
				sshContext.EXPECT().Permissions().Return(&sshPermissions)
			}
			// execute callback
			assert.Equal(
				tt, tc.keyFound, callback(sshContext, sshPublicKey), name)
			if tc.keyFound {
				assert.Equal(tt,
					sshPermissions.Permissions.Extensions,
					map[string]string{sshtoken.UserUUIDKey: userUUID.String()},
					name)
			} else {
				assert.Equal(tt, sshPermissions.Permissions.Extensions, nil, name)
			}
		})
	}
}
