package types

import (
	"fmt"
	"strings"
)

// AgentTeam is a first-class roster of agents with one named manager. Member
// requests that name no first approver of their own route to that manager. A
// team-wide grant is one entitlement per member, never one shared key.
type AgentTeam struct {
	TeamID      string
	TenantID    string
	Name        string
	ManagerID   string
	LeadActorID string
	MemberIDs   []string
}

// Validate refuses a team AAES cannot route or grant for.
func (t AgentTeam) Validate() error {
	if err := plainTeamID("team_id", t.TeamID); err != nil {
		return err
	}
	if err := plainTeamID("tenant_id", t.TenantID); err != nil {
		return err
	}
	if strings.TrimSpace(t.ManagerID) == "" {
		return fmt.Errorf("types: team %q names no manager; every team has a named person who decides member requests", t.TeamID)
	}
	if err := plainTeamID("manager_id", t.ManagerID); err != nil {
		return err
	}
	if t.LeadActorID != "" {
		if err := plainTeamID("lead_actor_id", t.LeadActorID); err != nil {
			return err
		}
	}
	if len(t.MemberIDs) == 0 {
		return fmt.Errorf("types: team %q names no members; a team with nobody in it cannot receive a grant", t.TeamID)
	}
	seen := map[string]bool{}
	leadOK := t.LeadActorID == ""
	for i, id := range t.MemberIDs {
		if err := plainTeamID("member_id", id); err != nil {
			return fmt.Errorf("types: team %q member %d: %v", t.TeamID, i, err)
		}
		if seen[id] {
			return fmt.Errorf("types: team %q names member %q twice", t.TeamID, id)
		}
		if id == t.ManagerID {
			return fmt.Errorf("types: team %q names its manager %q as a member; the manager is a person, not an agent on the roster", t.TeamID, id)
		}
		seen[id] = true
		if id == t.LeadActorID {
			leadOK = true
		}
	}
	if t.LeadActorID != "" && !leadOK {
		return fmt.Errorf("types: team %q names lead %q who is not a member; only a member may ask for the whole team", t.TeamID, t.LeadActorID)
	}
	return nil
}

// HasMember reports whether actorID is on the roster.
func (t AgentTeam) HasMember(actorID string) bool {
	id := strings.TrimSpace(actorID)
	for _, m := range t.MemberIDs {
		if m == id {
			return true
		}
	}
	return false
}

// MayRaiseForTeam reports whether actorID may ask for every member at once.
func (t AgentTeam) MayRaiseForTeam(actorID string) bool {
	id := strings.TrimSpace(actorID)
	if id == "" {
		return false
	}
	if t.LeadActorID != "" {
		return id == t.LeadActorID && t.HasMember(id)
	}
	return t.HasMember(id)
}

func (t AgentTeam) Clone() AgentTeam {
	out := t
	if t.MemberIDs != nil {
		out.MemberIDs = append([]string(nil), t.MemberIDs...)
	}
	return out
}

func plainTeamID(name, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("types: %s is required", name)
	}
	if trimmed != value {
		return fmt.Errorf("types: %s has surrounding whitespace", name)
	}
	if len(trimmed) > 160 {
		return fmt.Errorf("types: %s is %d bytes, the bound is 160", name, len(trimmed))
	}
	return nil
}
