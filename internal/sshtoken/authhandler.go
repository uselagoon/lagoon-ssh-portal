package sshtoken

import (
	"errors"
	"log/slog"

	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	gossh "golang.org/x/crypto/ssh"
)

const (
	userUUIDKey = "uselagoon/userUUID"
)

// permissionsMarshal takes the user UUID and stores it in the Extensions field
// of the ssh connection permissions.
//
// The Extensions field is the only way to safely pass information between
// handlers. See https://pkg.go.dev/vuln/GO-2024-3321
func permissionsMarshal(ctx ssh.Context, userUUID uuid.UUID) {
	ctx.Permissions().Extensions = map[string]string{
		userUUIDKey: userUUID.String(),
	}
}

// pubKeyAuth returns a ssh.PublicKeyHandler which accepts any key which
// matches a user, and adds the associated user UUID to the ssh permissions
// extensions map.
//
// Note that this function will be called for ALL public keys presented by the
// client, even if the client does not go on to prove ownership of the key by
// signing with it. See https://pkg.go.dev/vuln/GO-2024-3321
func pubKeyHandler(log *slog.Logger, ldb LagoonDBService) ssh.PublicKeyHandler {
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		log := log.With(slog.String("sessionID", ctx.SessionID()))
		// parse SSH public key
		pubKey, err := gossh.ParsePublicKey(key.Marshal())
		if err != nil {
			log.Warn("couldn't parse SSH public key", slog.Any("error", err))
			return false
		}
		// identify Lagoon user by ssh key fingerprint
		fingerprint := gossh.FingerprintSHA256(pubKey)
		log = log.With(slog.String("fingerprint", fingerprint))
		user, err := ldb.UserBySSHFingerprint(ctx, fingerprint)
		if err != nil {
			if errors.Is(err, lagoondb.ErrNoResult) {
				log.Debug("unknown SSH Fingerprint")
			} else {
				log.Warn("couldn't query for user by SSH key fingerprint",
					slog.Any("error", err))
			}
			return false
		}
		permissionsMarshal(ctx, *user.UUID)
		log.Info("authentication successful",
			slog.String("userUUID", user.UUID.String()))
		return true
	}
}
