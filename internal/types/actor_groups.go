package types

import (
	"fmt"
	"strings"
)

func (a ActorRef) validateGroupsAndRoles() error {
	for i, g := range a.Groups {
		if strings.TrimSpace(g) == "" {
			return fmt.Errorf("types: actor %q names an empty identity-provider group at index %d", a.ActorID, i)
		}
		for j := 0; j < len(g); j++ {
			if g[j] < 0x20 || g[j] == 0x7f {
				return fmt.Errorf("types: actor %q names a group containing a control character at index %d", a.ActorID, i)
			}
		}
	}
	for _, role := range a.Roles {
		if !role.Valid() {
			return fmt.Errorf("types: actor %q carries %q, which is not an operator role; the vocabulary is %s",
				a.ActorID, string(role), roleVocabulary())
		}
	}
	if a.Kind == KindAgent && len(a.Roles) > 0 {
		return fmt.Errorf("types: agent %q carries operator roles %s; roles gate the operator surfaces, which no agent may use",
			a.ActorID, RolesDisplayText(a.Roles))
	}
	return nil
}
