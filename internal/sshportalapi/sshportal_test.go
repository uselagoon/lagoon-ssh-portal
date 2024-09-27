package sshportalapi

import (
	"encoding/json"
	"testing"
)

func TestResponseMarshal(t *testing.T) {
	var testCases = map[string]struct {
		input  []byte
		expect bool
	}{
		"true":  {input: trueResponse, expect: true},
		"false": {input: falseResponse, expect: false},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			var value bool
			if err := json.Unmarshal(tc.input, &value); err != nil {
				tt.Fatalf("error unmarshaling data %v to bool", tc.input)
			}
			if value != tc.expect {
				tt.Fatalf("expected %v, got %v", tc.expect, value)
			}
		})
	}
}
