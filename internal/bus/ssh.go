// Package bus contains the definitions of the messages passed across NATS.
package bus

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	// SubjectSSHAccessQuery defines the NATS subject for SSH access queries.
	SubjectSSHAccessQuery = "lagoon.sshportal.api"
)

// SSHAccessQuery defines the structure of an SSH access query.
type SSHAccessQuery struct {
	SessionID      string
	SSHFingerprint string
	NamespaceName  string
	ProjectID      int
	EnvironmentID  int
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

// NATSClient is a NATS client.
type NATSClient struct {
	conn       *nats.Conn
	reqTimeout time.Duration
}

// NewNATSClient constructs a new NATS client which connects to the given
// srvAddr. It logs to the given log, and calls the given context.CancelFunc
// when the NATS connection closes.
//
// The idea is that when the connection closes on the other end, this function
// must be called again to construct a new client.
func NewNATSClient(
	srvAddr string,
	reqTimeout time.Duration,
	log *slog.Logger,
	cancel context.CancelFunc,
) (*NATSClient, error) {
	// get nats server connection
	conn, err := nats.Connect(
		srvAddr,
		nats.Name("ssh-portal"),
		// cancel upstream context on connection close
		nats.ClosedHandler(func(_ *nats.Conn) {
			log.Error("nats connection closed")
			cancel()
		}),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn("nats disconnected", slog.Any("error", err))
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Info("nats reconnected", slog.String("url", nc.ConnectedUrl()))
		}))
	if err != nil {
		return nil, fmt.Errorf("couldn't connect to NATS server: %v", err)
	}
	return &NATSClient{
		conn:       conn,
		reqTimeout: reqTimeout,
	}, nil
}

// Close calls Close() on the underlying NATS connection.
func (c *NATSClient) Close() {
	c.conn.Close()
}

// KeyCanAccessEnvironment returns true if the given key can access the given
// environment, or false otherwise.
func (c *NATSClient) KeyCanAccessEnvironment(
	sessionID,
	sshFingerprint,
	namespaceName string,
	projectID,
	environmentID int,
) (bool, error) {
	// construct ssh access query
	queryData, err := json.Marshal(SSHAccessQuery{
		SessionID:      sessionID,
		SSHFingerprint: sshFingerprint,
		NamespaceName:  namespaceName,
		ProjectID:      projectID,
		EnvironmentID:  environmentID,
	})
	if err != nil {
		return false, fmt.Errorf("couldn't marshal NATS request: %v", err)
	}
	// send query
	msg, err := c.conn.Request(
		SubjectSSHAccessQuery,
		queryData,
		c.reqTimeout)
	if err != nil {
		return false, fmt.Errorf("couldn't make NATS request: %v", err)
	}
	// handle response
	var ok bool
	if err := json.Unmarshal(msg.Data, &ok); err != nil {
		return false, fmt.Errorf("couldn't unmarshal response: %v", err)
	}
	return ok, nil
}
