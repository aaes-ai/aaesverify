package types

import (
	"strings"
	"testing"
)

func TestTeamValidationRefusesAmbiguousRoster(t *testing.T) {
	base := AgentTeam{TeamID: "team", TenantID: "tenant", ManagerID: "manager", LeadActorID: "agent", MemberIDs: []string{"agent"}}
	cases := map[string]func(*AgentTeam){
		"tenant":             func(v *AgentTeam) { v.TenantID = "" },
		"manager whitespace": func(v *AgentTeam) { v.ManagerID = " manager" },
		"lead whitespace":    func(v *AgentTeam) { v.LeadActorID = " agent" },
		"empty roster":       func(v *AgentTeam) { v.MemberIDs = nil },
		"member whitespace":  func(v *AgentTeam) { v.MemberIDs = []string{" agent"} },
		"long id":            func(v *AgentTeam) { v.TeamID = strings.Repeat("a", 161) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := base.Clone()
			mutate(&v)
			if err := v.Validate(); err == nil {
				t.Fatal("ambiguous roster accepted")
			}
		})
	}
	if base.MayRaiseForTeam(" ") {
		t.Fatal("empty actor may raise for team")
	}
	if got := ActionGroupIrreversible.Label(); got != "irreversible" {
		t.Fatal(got)
	}
	if got := ActionGroup("future").Label(); got != "future" {
		t.Fatal(got)
	}
	if got := ActionGroupRun.Label(); got != "run" {
		t.Fatal(got)
	}
}
