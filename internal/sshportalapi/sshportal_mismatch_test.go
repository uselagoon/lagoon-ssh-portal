package sshportalapi_test

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/uselagoon/ssh-portal/internal/bus"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
	"github.com/uselagoon/ssh-portal/internal/sshportalapi"
	"go.uber.org/mock/gomock"
)

func TestSSHPortalIDMismatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	ldb := NewMockLagoonDBService(ctrl)
	ns := NewMockNATSService(ctrl)
	query := bus.SSHAccessQuery{
		SSHFingerprint: "SHA256:abc",
		NamespaceName:  "project-main",
		ProjectID:      1,
		EnvironmentID:  2,
	}
	data, err := json.Marshal(query)
	if err != nil {
		t.Fatalf("couldn't marshal query: %v", err)
	}
	ldb.EXPECT().
		EnvironmentByNamespaceName(gomock.Any(), query.NamespaceName).
		Return(&lagoondb.Environment{
			ID:            99,
			NamespaceName: query.NamespaceName,
			ProjectID:     98,
		}, nil)
	ns.EXPECT().
		Publish("reply.subject", sshportalapi.FalseResponse).
		Return(nil)
	// mismatch branch returns before permission checks so nil permission is
	// sufficient
	handler := sshportalapi.SSHPortal(
		t.Context(),
		slog.New(slog.NewJSONHandler(t.Output(), nil)),
		ns,
		nil,
		ldb,
	)
	handler(&nats.Msg{
		Reply: "reply.subject",
		Data:  data,
	})
}
