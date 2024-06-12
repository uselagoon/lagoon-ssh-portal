package sshserver

import (
	"slices"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestDisableSHA1Kex(t *testing.T) {
	t.Run("no sha1", func(tt *testing.T) {
		conf := serverConfig(nil)
		assert.Equal(tt, false,
			slices.Contains(conf.Config.KeyExchanges, "diffie-hellman-group14-sha1"), "no sha1")
	})
}

func TestMaxAuthTries(t *testing.T) {
	t.Run("MaxAuthTries", func(tt *testing.T) {
		conf := serverConfig(nil)
		assert.Equal(tt, 18, conf.MaxAuthTries, "MaxAuthTries")
	})
}
