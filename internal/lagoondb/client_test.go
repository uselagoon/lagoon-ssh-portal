package lagoondb_test

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alecthomas/assert/v2"
	"github.com/uselagoon/ssh-portal/internal/lagoondb"
)

func TestLastUsed(t *testing.T) {
	var testCases = map[string]struct {
		fingerprint string
		used        time.Time
		usedString  string
		expectError bool
	}{
		"right time": {
			fingerprint: "SHA256:yARVMVDnP2B2QzTvE8eSs5ZZlkZEoMFEIKjtYv1adfU",
			used:        time.Unix(1719825567, 0),
			usedString:  "2024-07-01 09:19:27",
			expectError: false,
		},
		"wrong time": {
			fingerprint: "SHA256:yARVMVDnP2B2QzTvE8eSs5ZZlkZEoMFEIKjtYv1adfU",
			used:        time.Unix(1719825567, 0),
			usedString:  "2024-07-01 17:19:27",
			expectError: true,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			// set up mocks
			mockDB, mock, err := sqlmock.New()
			assert.NoError(tt, err, name)
			mock.ExpectExec(
				`UPDATE ssh_key `+
					`SET last_used = (.+) `+
					`WHERE key_fingerprint = (.+)`).
				WithArgs(tc.usedString, tc.fingerprint).
				WillReturnResult(sqlmock.NewErrorResult(nil))
			// execute expected database operations
			db := lagoondb.NewClientFromDB(mockDB)
			err = db.SSHKeyUsed(context.Background(), tc.fingerprint, tc.used)
			if tc.expectError {
				assert.Error(tt, err, name)
			} else {
				assert.NoError(tt, err, name)
			}
			// check expectations
			err = mock.ExpectationsWereMet()
			if tc.expectError {
				assert.Error(tt, err, name)
			} else {
				assert.NoError(tt, err, name)
			}
		})
	}
}
