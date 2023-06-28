package keycloak_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/uselagoon/ssh-portal/internal/keycloak"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func TestUnmarshalLagoonClaims(t *testing.T) {
	var testCases = map[string]struct {
		input  []byte
		expect *keycloak.LagoonClaims
	}{
		"two groups": {
			input: []byte(`{
		"group_lagoon_project_ids": [
			"{\"credentialtest-group1\":[1]}",
				"{\"ci-group\":[3,4,5,6,7,8,9,10,11,12,17,14,16,20,21,24,19,23,31]}"]}`),
			expect: &keycloak.LagoonClaims{
				RealmRoles: nil,
				UserGroups: nil,
				GroupProjectIDs: map[string][]int{
					"credentialtest-group1": {1},
					"ci-group": {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 17, 14, 16, 20, 21, 24,
						19, 23, 31},
				},
				RegisteredClaims: jwt.RegisteredClaims{},
			},
		},
		"multiple attributes": {
			input: []byte(`{
				"jti":"ba279e79-4f38-43ae-83e7-fe461aad59d1",
				"exp":1637296288,
				"nbf":0,
				"iat":1637295988,
				"iss":"http://lagoon-core-keycloak:8080/auth/realms/lagoon",
				"aud":"account",
				"sub":"91435afe-ba81-406b-9308-f80b79fae350",
				"typ":"Bearer",
				"azp":"service-api",
				"auth_time":0,
				"session_state":"14ffd91a-86e3-4ce3-93b7-2df3591fcdaf",
				"acr":"1",
				"realm_access":
				 {"roles":
				  ["owner",
				   "platform-owner",
				   "offline_access",
				   "guest",
				   "reporter",
				   "developer",
				   "uma_authorization",
				   "maintainer"]},
				"resource_access":
				 {"account":
				  {"roles":["manage-account", "manage-account-links", "view-profile"]}},
				"scope":"profile email",
				"group_membership":
				 ["/ci-group/ci-group-owner",
				  "/credentialtest-group1/credentialtest-group1-owner"],
				"realm_roles":
				 ["owner",
				  "platform-owner",
				  "offline_access",
				  "guest",
				  "reporter",
				  "developer",
				  "uma_authorization",
				  "maintainer"],
				"email_verified":true,
				"group_lagoon_project_ids":
				["{\"credentialtest-group1\":[1]}",
					"{\"ci-group\":[3,4,5,6,7,8,9,10,11,12,17,14,16,20,21,24,19,23,31]}"]
				}`),
			expect: &keycloak.LagoonClaims{
				RealmRoles: []string{
					"owner",
					"platform-owner",
					"offline_access",
					"guest",
					"reporter",
					"developer",
					"uma_authorization",
					"maintainer"},
				UserGroups: []string{
					"/ci-group/ci-group-owner",
					"/credentialtest-group1/credentialtest-group1-owner"},
				GroupProjectIDs: map[string][]int{
					"credentialtest-group1": {1},
					"ci-group": {3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 17, 14, 16, 20, 21, 24,
						19, 23, 31},
				},
				AuthorizedParty: "service-api",
				RegisteredClaims: jwt.RegisteredClaims{
					ID:       "ba279e79-4f38-43ae-83e7-fe461aad59d1",
					Issuer:   "http://lagoon-core-keycloak:8080/auth/realms/lagoon",
					Subject:  "91435afe-ba81-406b-9308-f80b79fae350",
					Audience: jwt.ClaimStrings{"account"},
					ExpiresAt: &jwt.NumericDate{
						Time: time.Date(2021, time.November, 19, 4, 31, 28, 0, time.UTC).Local(),
					},
					NotBefore: &jwt.NumericDate{
						Time: time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC).Local(),
					},
					IssuedAt: &jwt.NumericDate{
						Time: time.Date(2021, time.November, 19, 4, 26, 28, 0, time.UTC).Local(),
					},
				},
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			var sac *keycloak.LagoonClaims
			err := json.Unmarshal(tc.input, &sac)
			if err != nil {
				tt.Fatal(err)
			}
			assert.Equal(tt, sac, tc.expect)
		})
	}
}

func TestValidateTokenClaims(t *testing.T) {
	// set up logger
	log := zap.Must(zap.NewDevelopment())
	// set up test cases
	var testCases = map[string]struct {
		input          *oauth2.Token
		validationTime time.Time
		expectClaims   *keycloak.LagoonClaims
		expectError    bool
	}{
		"valid token": {
			input: &oauth2.Token{
				AccessToken: "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJrd0ZLNVlwMlI3QkxZalc4Z1NZNkxzQjNsSVlzcFI1TmlFdW5GRUdxZGdnIn0.eyJleHAiOjE2Njg0MzkyNDQsImlhdCI6MTY2ODQzODk0NCwianRpIjoiYjcwYzQyNTAtYTQxOS00MGYxLThlM2EtYTg3YzU2ZjJjNGEzIiwiaXNzIjoiaHR0cDovL2xhZ29vbi1jb3JlLWtleWNsb2FrOjgwODAvYXV0aC9yZWFsbXMvbGFnb29uIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjdiYzk4MmExLWM5MGEtNDIyOS04YjVmLTgxNmMxOGQ5ZGZiYyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImF1dGgtc2VydmVyIiwic2Vzc2lvbl9zdGF0ZSI6ImViZWNlNTAxLWIzMWUtNDBiNy1iMWIwLTU4MjhkYWY0ZmE3OSIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsicGxhdGZvcm0tb3duZXIiLCJvZmZsaW5lX2FjY2VzcyIsImFkbWluIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJzaWQiOiJlYmVjZTUwMS1iMzFlLTQwYjctYjFiMC01ODI4ZGFmNGZhNzkiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6ImxhZ29vbmFkbWluIn0.GaVMQSKpZldYpY0bmNVY1EJKf8pZVq8bps1-xPLQvWn2KlnjkVFKMuE34j66HRKJ3ZJybDyCkBAIr2ImzunFy5_ur9GdXRBHOo5RtnpNL9YxGwUTWNAtTqOqXMi4QkY4AHfMkgHAhZRSMP3oADjiv2hOkIeummTXo6KTY7fOmumz1UkvRyfeWt-6tcSWrCBezvuMXhwJUF7_EuEPdLaNpiQ_H1wqhamHg1YZ6QzJ5z7NcD8f6dc-h7qUhTBlMGOGEeWThmxudrzOuHkcx6LBzutzPdQNhTo7d2PsAa4igz3RXZV65BBVMkqp8v8k1ZIxb2a_6DHngd2T-XDjzNFREQ",
			},
			validationTime: time.Date(2022, time.November, 14, 15, 16, 0, 0, time.UTC),
			expectClaims: &keycloak.LagoonClaims{
				AuthorizedParty: "auth-server",
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "http://lagoon-core-keycloak:8080/auth/realms/lagoon",
					Subject:   "7bc982a1-c90a-4229-8b5f-816c18d9dfbc",
					Audience:  jwt.ClaimStrings{"account"},
					ExpiresAt: jwt.NewNumericDate(time.Date(2022, time.November, 14, 15, 20, 44, 0, time.UTC).In(time.Local)),
					IssuedAt:  jwt.NewNumericDate(time.Date(2022, time.November, 14, 15, 15, 44, 0, time.UTC).In(time.Local)),
					ID:        "b70c4250-a419-40f1-8e3a-a87c56f2c4a3",
				},
			},
			expectError: false,
		},
		"invalid signature (last 5 chars)": {
			input: &oauth2.Token{
				AccessToken: "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJrd0ZLNVlwMlI3QkxZalc4Z1NZNkxzQjNsSVlzcFI1TmlFdW5GRUdxZGdnIn0.eyJleHAiOjE2Njg0MzkyNDQsImlhdCI6MTY2ODQzODk0NCwianRpIjoiYjcwYzQyNTAtYTQxOS00MGYxLThlM2EtYTg3YzU2ZjJjNGEzIiwiaXNzIjoiaHR0cDovL2xhZ29vbi1jb3JlLWtleWNsb2FrOjgwODAvYXV0aC9yZWFsbXMvbGFnb29uIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjdiYzk4MmExLWM5MGEtNDIyOS04YjVmLTgxNmMxOGQ5ZGZiYyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImF1dGgtc2VydmVyIiwic2Vzc2lvbl9zdGF0ZSI6ImViZWNlNTAxLWIzMWUtNDBiNy1iMWIwLTU4MjhkYWY0ZmE3OSIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsicGxhdGZvcm0tb3duZXIiLCJvZmZsaW5lX2FjY2VzcyIsImFkbWluIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJzaWQiOiJlYmVjZTUwMS1iMzFlLTQwYjctYjFiMC01ODI4ZGFmNGZhNzkiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6ImxhZ29vbmFkbWluIn0.GaVMQSKpZldYpY0bmNVY1EJKf8pZVq8bps1-xPLQvWn2KlnjkVFKMuE34j66HRKJ3ZJybDyCkBAIr2ImzunFy5_ur9GdXRBHOo5RtnpNL9YxGwUTWNAtTqOqXMi4QkY4AHfMkgHAhZRSMP3oADjiv2hOkIeummTXo6KTY7fOmumz1UkvRyfeWt-6tcSWrCBezvuMXhwJUF7_EuEPdLaNpiQ_H1wqhamHg1YZ6QzJ5z7NcD8f6dc-h7qUhTBlMGOGEeWThmxudrzOuHkcx6LBzutzPdQNhTo7d2PsAa4igz3RXZV65BBVMkqp8v8k1ZIxb2a_6DHngd2T-XDjzZZZZZ",
			},
			validationTime: time.Date(2022, time.November, 14, 15, 16, 0, 0, time.UTC),
			expectClaims:   nil,
			expectError:    true,
		},
		// https://www.scottbrady91.com/tools/jwt
		"invalid signature (wrong key)": {
			input: &oauth2.Token{
				AccessToken: "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjY2OTBjMzMxYzZjMDY0ZjI4YWEyMGRkZjg4YjY0OGJmIn0.eyJpc3MiOiJodHRwczovL2lkcC5sb2NhbCIsImF1ZCI6ImFwaTEiLCJzdWIiOiI1YmU4NjM1OTA3M2M0MzRiYWQyZGEzOTMyMjIyZGFiZSIsImNsaWVudF9pZCI6Im15X2NsaWVudF9hcHAiLCJleHAiOjE2Njg1MjQ0NTQsImlhdCI6MTY2ODUyMDg1NCwianRpIjoiMTgyM2JmMDI2NWVjYzc5NTc0YzY0ZTAyNmM1ZGY1OTMifQ.KaA0oA0aJETMARLoDYj_0ErcDER5p7KXzsbWyzeYFA_sqvZYvI-B__NtE6ZSbbaROeJi2T7y-V4MTrUlqcmjTSOu51ifPegIWb-o9eiVCInXp2Roc8O1oWXZQ2hStJoc2BnMk4zFi6W2MDm9aD3jGTNsstGQ7X3moD4Pmv9zAZATYVyIxFPFPaySVVsX1bpfyEOlcqN4tFBWb-AAcZ71pE8ZUQ-kquE2M2swJSnVSPDN6wV-iFob6kadTGMmJQ-8n8OEptUpuwG6xEYqJlX4mC9CxGJb9tZnCQ5O3kyN6suRAsKZlVLp63FbvvV5KLAJ01l8CRNPr1JMnAkunpQlLkPLclc_RnBhjSPgwSEKTkWdP_CLU8ZUGS70pqrrplmVCXOzwxAmOVMLtJeh2x6eRQ24cIDyTU98h1z6HRbU_XOUfgDpylQn9uQYTMAg_vTdvylzZtN5L8nT7BLCoulayUqsg8l9Q8iZouTULLSSqCa2wmUvEz41Yu0GvciJMgQg",
			},
			validationTime: time.Date(2022, time.November, 14, 15, 16, 0, 0, time.UTC),
			expectClaims:   nil,
			expectError:    true,
		},
		// https://www.scottbrady91.com/tools/jwt
		"invalid signature (wrong key and alg)": {
			input: &oauth2.Token{
				AccessToken: "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzUxMiIsImtpZCI6ImVjYjNlMjg3ODlhOTM4MGIzZWQ2NGI1NzcyZTExNjhhIn0.eyJpc3MiOiJodHRwczovL2lkcC5sb2NhbCIsImF1ZCI6ImFwaTEiLCJzdWIiOiI1YmU4NjM1OTA3M2M0MzRiYWQyZGEzOTMyMjIyZGFiZSIsImNsaWVudF9pZCI6Im15X2NsaWVudF9hcHAiLCJleHAiOjE2Njg1MjQ0NTQsImlhdCI6MTY2ODUyMDg1NCwianRpIjoiMTgyM2JmMDI2NWVjYzc5NTc0YzY0ZTAyNmM1ZGY1OTMifQ.S8Y01w9NJhuFvT6xxGU3t2GXsd1UzQKAOUS3vdUFrzuy1dg_0BHszE-mTeg400jQQfc0SgORStAVQc-8ewBwKikCBbonVC9Jx7dMz3L-rZevpNd4zEfcevpbqzZtuzgVWByIzfQfcV57pqRHVMs6xA-3P1isfDZpqLXyGtwjBlueOLkiOIFR8iMyQAV4Toyqn_tbYT51yUmweolt4b2hBvOvXyO-o2-lGoPsJwr3JBDMrjEkRNOkmmuBM0QXzs5LfFuIU0QYQLGwj0Oa8e3Hcdjp_69B2ja1pmDpvqBq1rw-5tn1QV4mTsp_FFc12NKPdewZUhEKHjbAVK7L7NanO3IpCIFg0jpBTFySpN0X7Y_Wwu6cbUK39xAOdadZXSqrSslwr4twH9NtQ3dG01EzA9HemHzB7AhaZ2eD8_SpohBCGvMQkBGGdXREZbXW8_nLwwMNi_gNr1BqVJvmqV2eRWPrxEyPBtL5jD6jNc_Vffj-Tua49Rd8EECKAhh8QC0F",
			},
			validationTime: time.Date(2022, time.November, 14, 15, 16, 0, 0, time.UTC),
			expectClaims:   nil,
			expectError:    true,
		},
		// https://token.dev/
		"no signature (alg=none)": {
			input: &oauth2.Token{
				AccessToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY2ODU2NzA0NywiZXhwIjoxNjY4NTcwNjQ3fQ",
			},
			validationTime: time.Date(2022, time.November, 14, 15, 16, 0, 0, time.UTC),
			expectClaims:   nil,
			expectError:    true,
		},
		// https://token.dev/
		"invalid signature (alg=none)": {
			input: &oauth2.Token{
				// copied the previous case's AccessToken and appended a signature
				AccessToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY2ODU2NzA0NywiZXhwIjoxNjY4NTcwNjQ3fQ.dkyKxuTU3yKiBPp8UEmnSrmX_CDTFlVrwI3g3SQW2-7y5LBX6EZ0tbrfIxySQOflp0u_HYeBO1yoeV5jHb4xEb32i7yI3zHLHQmt3oF1BouMo89gEUKIMpN6aePJ80SPVH8QzrOvI6BfMlODNeCf7vmKSNLN8f_OOzQFmDdGSoWWl47KcAHEnGIjeFgBy77y1fpLhD2ApkE-S7wpWEHGL5PpskWtLVVY5-0R8feY5zP7C_qkdG-7tvo-3zrYx9aDMOhSmellthNxB1HuGF-WMHQhAZYA5ej83ZQK3qZsRFl176Bs3RV5hw2IU-uMrLmeFJCD2Cstnd8fPnCcOh66Wg",
			},
			validationTime: time.Date(2022, time.November, 14, 15, 16, 0, 0, time.UTC),
			expectClaims:   nil,
			expectError:    true,
		},
	}
	// init client
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			// start mock keycloak server to serve the realm metadata (including the
			// RSA public key) during keycloak.NewClient().
			ts := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					f, err := os.Open("testdata/realm.metadata.json")
					if err != nil {
						tt.Fatal(err)
						return
					}
					_, err = io.Copy(w, f)
					if err != nil {
						tt.Fatal(err)
					}
				}))
			defer ts.Close()
			// init keycloak client
			// note: client secret is empty because it isn't used in this test, but
			// client ID is checked against azp in the token.
			k, err := keycloak.NewClient(context.Background(), log, ts.URL,
				"auth-server", "")
			if err != nil {
				tt.Fatal(err)
			}
			// run the validation
			claims, err := k.ValidateToken(tc.input, "sub",
				jwt.WithTimeFunc(func() time.Time { return tc.validationTime }))
			// check the response
			if tc.expectError {
				assert.Error(tt, err)
				tt.Log(err)
			} else {
				assert.NoError(tt, err)
			}
			assert.Equal(tt, tc.expectClaims, claims)
		})
	}
}
