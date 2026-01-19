package sshserver

import (
	"slices"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestDisableSHA1Kex(t *testing.T) {
	var testCases = map[string]struct {
		input  string
		expect bool
	}{
		"no sha1": {input: "diffie-hellman-group14-sha1", expect: false},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			conf := disableInsecureAlgos(nil)
			assert.Equal(tt, tc.expect,
				slices.Contains(conf.KeyExchanges, tc.input), name)
		})
	}
}
