// Package bus contains the definitions of the messages passed across NATS.
package bus

import "log/slog"

const (
	// SubjectSSHAccessQuery defines the NATS subject for SSH access queries.
	SubjectSSHAccessQuery = "lagoon.sshportal.api"
)

// SSHAccessQuery defines the structure of an SSH access query.
type SSHAccessQuery struct {
	SSHFingerprint string
	NamespaceName  string
	ProjectID      int
	EnvironmentID  int
	SessionID      string
}

// LogValue implements the slog.LogValuer interface.
func (q SSHAccessQuery) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("sshFingerprint", q.SSHFingerprint),
		slog.String("namespaceName", q.NamespaceName),
		slog.Int("projectID", q.ProjectID),
		slog.Int("environmentID", q.EnvironmentID),
		slog.String("sessionID", q.SessionID),
	)
}
