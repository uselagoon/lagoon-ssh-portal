package keycloak

import "encoding/json"

type regularAttributes struct {
	RealmRoles []string `json:"realm_roles"`
	UserGroups []string `json:"group_membership"`
}

// attributes injected into the access token by keycloak
type userAttributes struct {
	regularAttributes
	GroupProjectIDs map[string][]int
}

type stringAttributes struct {
	GroupPIDs []string `json:"group_lagoon_project_ids"`
}

func (u *userAttributes) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &u.regularAttributes); err != nil {
		return err
	}
	// unmarshal the double-encoded group-pid attributes
	var s stringAttributes
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	var gpaMaps []map[string][]int
	for _, gpa := range s.GroupPIDs {
		var gpaMap map[string][]int
		if err := json.Unmarshal([]byte(gpa), &gpaMap); err != nil {
			return err
		}
		gpaMaps = append(gpaMaps, gpaMap)
	}
	u.GroupProjectIDs = map[string][]int{}
	for _, gpaMap := range gpaMaps {
		for k, v := range gpaMap {
			u.GroupProjectIDs[k] = v
		}
	}
	return nil
}
