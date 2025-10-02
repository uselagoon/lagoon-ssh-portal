package sshserver

import (
	"log/slog"
	"strconv"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

const (
	environmentIDKey   = "uselagoon/environmentID"
	environmentNameKey = "uselagoon/environmentName"
	projectIDKey       = "uselagoon/projectID"
	projectNameKey     = "uselagoon/projectName"
)

// permissionsMarshal takes details of the Lagoon environment and stores them
// in the Extensions field of the ssh connection permissions.
//
// The Extensions field is the only way to safely pass information between
// handlers. See https://pkg.go.dev/vuln/GO-2024-3321
func permissionsMarshal(ctx ssh.Context, eid, pid int, ename, pname string) {
	ctx.Permissions().Extensions = map[string]string{
		environmentIDKey:   strconv.Itoa(eid),
		environmentNameKey: ename,
		projectIDKey:       strconv.Itoa(pid),
		projectNameKey:     pname,
	}
}

// pubKeyHandler returns a ssh.PublicKeyHandler which queries the remote
// ssh-portal-api for Lagoon SSH authorization.
//
// Note that this function will be called for ALL public keys presented by the
// client, even if the client does not go on to prove ownership of the key by
// signing with it. See https://pkg.go.dev/vuln/GO-2024-3321
func pubKeyHandler(
	log *slog.Logger,
	nc NATSService,
	c K8SAPIService,
) ssh.PublicKeyHandler {
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		log := log.With(
			slog.String("sessionID", ctx.SessionID()),
			slog.String("namespace", ctx.User()),
		)
		// get Lagoon labels from namespace if available
		eid, pid, ename, pname, err := c.NamespaceDetails(ctx, ctx.User())
		if err != nil {
			log.Debug("couldn't get namespace details",
				slog.String("namespace", ctx.User()), slog.Any("error", err))
			return false
		}
		fingerprint := gossh.FingerprintSHA256(key)
		log = log.With(slog.String("fingerprint", fingerprint))
		ok, err := nc.KeyCanAccessEnvironment(
			ctx.SessionID(),
			fingerprint,
			ctx.User(),
			pid,
			eid,
		)
		if err != nil {
			log.Warn("couldn't query permission via NATS", slog.Any("error", err))
			return false
		}
		// handle response
		if !ok {
			log.Debug("SSH access not authorized")
			return false
		}
		log.Debug("SSH access authorized")
		permissionsMarshal(ctx, eid, pid, ename, pname)
		return true
	}
}
