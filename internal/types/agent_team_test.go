package types

import "testing"

func TestAgentTeamValidateAndRaise(t *testing.T) {
	team := AgentTeam{
		TeamID: "team-payments", TenantID: "t1", Name: "payments",
		ManagerID: "human-1", LeadActorID: "agent-lead",
		MemberIDs: []string{"agent-lead", "agent-2"},
	}
	if err := team.Validate(); err != nil {
		t.Fatal(err)
	}
	if !team.HasMember("agent-2") || team.HasMember("human-1") {
		t.Fatalf("membership = lead=%v other=%v manager=%v", team.HasMember("agent-lead"), team.HasMember("agent-2"), team.HasMember("human-1"))
	}
	if !team.MayRaiseForTeam("agent-lead") || team.MayRaiseForTeam("agent-2") {
		t.Fatal("only the named lead may ask for the whole team")
	}
	cloned := team.Clone()
	cloned.MemberIDs[0] = "mutated"
	if team.MemberIDs[0] != "agent-lead" {
		t.Fatal("Clone must copy the roster")
	}
}

func TestAgentTeamValidateRefusals(t *testing.T) {
	base := AgentTeam{
		TeamID: "team-1", TenantID: "t1", ManagerID: "human-1", MemberIDs: []string{"agent-1"},
	}
	if err := (AgentTeam{}).Validate(); err == nil {
		t.Fatal("empty team")
	}
	noMgr := base
	noMgr.ManagerID = ""
	if err := noMgr.Validate(); err == nil {
		t.Fatal("no manager")
	}
	dup := base
	dup.MemberIDs = []string{"agent-1", "agent-1"}
	if err := dup.Validate(); err == nil {
		t.Fatal("duplicate member")
	}
	mgrMember := base
	mgrMember.MemberIDs = []string{"human-1"}
	if err := mgrMember.Validate(); err == nil {
		t.Fatal("manager as member")
	}
	outsideLead := base
	outsideLead.LeadActorID = "agent-other"
	if err := outsideLead.Validate(); err == nil {
		t.Fatal("lead outside roster")
	}
	if (AgentTeam{LeadActorID: "agent-1"}).MayRaiseForTeam("agent-1") {
		t.Fatal("a lead who is not a member must not raise")
	}
	if !base.MayRaiseForTeam("agent-1") {
		t.Fatal("with no lead, a member may ask for the team")
	}
}

func TestActorRefRefusesTeamOnHumansAndAwayOnAgents(t *testing.T) {
	human := ActorRef{ActorID: "h1", TenantID: "t1", Kind: KindHuman, TeamID: "team-1"}
	if err := human.Validate(); err == nil {
		t.Fatal("a named person with a team_id")
	}
	agent := ActorRef{ActorID: "a1", TenantID: "t1", Kind: KindAgent, Sponsor: "h1", Away: true, Successor: "h2"}
	if err := agent.Validate(); err == nil {
		t.Fatal("an agent marked away")
	}
}
