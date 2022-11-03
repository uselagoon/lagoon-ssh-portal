package keycloak

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v4"
)

type groupProjectIDs map[string][]int

func (gpids *groupProjectIDs) UnmarshalJSON(data []byte) error {
	// unmarshal the double-encoded group-pid attributes
	var gpas []string
	if err := json.Unmarshal(data, &gpas); err != nil {
		return err
	}
	// convert the slice of encoded group-pid attributes into a slice of
	// group-pid maps
	var gpms []map[string][]int
	for _, gpa := range gpas {
		var gpm map[string][]int
		if err := json.Unmarshal([]byte(gpa), &gpm); err != nil {
			return err
		}
		gpms = append(gpms, gpm)
	}
	// flatten the slice of group-pid maps into a single map
	*gpids = groupProjectIDs{}
	for _, gpm := range gpms {
		for k, v := range gpm {
			(*gpids)[k] = v
		}
	}
	return nil
}

// SSHAPIClaims contains the relevant claims for use by the SSH API service.
type SSHAPIClaims struct {
	RealmRoles      []string        `json:"realm_roles"`
	UserGroups      []string        `json:"group_membership"`
	GroupProjectIDs groupProjectIDs `json:"group_lagoon_project_ids"`
	AuthorizedParty string          `json:"azp"`
	jwt.RegisteredClaims
}
