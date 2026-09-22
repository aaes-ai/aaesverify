package types

import (
	"strings"
	"testing"
)

func TestParseRoleVocabularyAndTolerance(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Role
		ok   bool
	}{
		{"approver", RoleApprover, true},
		{"  Owner ", RoleOwner, true},
		{"SPONSOR", RoleSponsor, true},
		{"auditor", RoleAuditor, true},
		{"Admin", RoleAdmin, true},
		{"operator", "", false},
		{"", "", false},
		{"approver,owner", "", false},
	} {
		got, err := ParseRole(tc.in)
		if tc.ok && (err != nil || got != tc.want) {
			t.Fatalf("ParseRole(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
		if !tc.ok {
			if err == nil {
				t.Fatalf("ParseRole(%q) was accepted as %q; an unknown role must be refused", tc.in, got)
			}
			if !strings.Contains(err.Error(), "approver, owner, sponsor, auditor, admin") {
				t.Fatalf("ParseRole(%q) refusal does not name the vocabulary: %v", tc.in, err)
			}
		}
	}
}

func TestRolePermissionsAreTheOnesTheConsoleGatesOn(t *testing.T) {
	// The rules are asserted as a table because they are the product claim: an
	// auditor cannot approve, and only an admin may change the identity policy.
	approve := map[Role]bool{
		RoleApprover: true, RoleOwner: false, RoleSponsor: false, RoleAuditor: false, RoleAdmin: true,
	}
	policy := map[Role]bool{
		RoleApprover: false, RoleOwner: false, RoleSponsor: false, RoleAuditor: false, RoleAdmin: true,
	}
	end := map[Role]bool{
		RoleApprover: true, RoleOwner: true, RoleSponsor: false, RoleAuditor: false, RoleAdmin: true,
	}
	for _, r := range Roles() {
		if got := r.CanApprove(); got != approve[r] {
			t.Fatalf("%s.CanApprove() = %v, want %v", r, got, approve[r])
		}
		if got := r.CanChangeIdentityPolicy(); got != policy[r] {
			t.Fatalf("%s.CanChangeIdentityPolicy() = %v, want %v", r, got, policy[r])
		}
		if got := r.CanEndEntitlement(); got != end[r] {
			t.Fatalf("%s.CanEndEntitlement() = %v, want %v", r, got, end[r])
		}
		if r.ReadOnly() != (r == RoleAuditor) {
			t.Fatalf("%s.ReadOnly() = %v", r, r.ReadOnly())
		}
	}
}

func TestRoleRefusalNamesTheMissingRoleAndWhatWasCarried(t *testing.T) {
	err := RoleRefusalError{Role: RoleApprover, Carried: []Role{RoleAuditor}, Operation: "deciding an approval"}
	msg := err.Error()
	for _, want := range []string{"approver", "auditor", "deciding an approval"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("refusal %q does not name %q", msg, want)
		}
	}
}

func TestSortRolesAndHasRoleIgnoreOrder(t *testing.T) {
	roles := []Role{RoleAdmin, RoleApprover, RoleAuditor}
	SortRoles(roles)
	want := []Role{RoleApprover, RoleAuditor, RoleAdmin}
	for i := range want {
		if roles[i] != want[i] {
			t.Fatalf("SortRoles = %v, want %v", roles, want)
		}
	}
	if !HasRole(roles, RoleAuditor) || HasRole(roles, RoleOwner) || HasRole(roles, Role("")) {
		t.Fatalf("HasRole answered wrongly for %v", roles)
	}
	got, err := ParseRoleList([]string{"auditor", "Auditor", "approver"})
	if err != nil || len(got) != 2 || got[0] != RoleApprover || got[1] != RoleAuditor {
		t.Fatalf("ParseRoleList = %v, %v", got, err)
	}
}

func TestActorValidateRefusesUnusableOperatorFields(t *testing.T) {
	base := ActorRef{ActorID: "h1", Kind: KindHuman, TenantID: "t1"}
	if err := base.Validate(); err != nil {
		t.Fatalf("a person with no subject, groups or roles must register: %v", err)
	}
	withEmptyGroup := base
	withEmptyGroup.Groups = []string{"eng", "  "}
	if err := withEmptyGroup.Validate(); err == nil {
		t.Fatal("an empty group name was accepted")
	}
	withBadRole := base
	withBadRole.Roles = []Role{"root"}
	if err := withBadRole.Validate(); err == nil {
		t.Fatal("an unknown role was accepted")
	}
	agentWithRole := ActorRef{ActorID: "a1", Kind: KindAgent, TenantID: "t1", Sponsor: "h1", Roles: []Role{RoleAdmin}}
	if err := agentWithRole.Validate(); err == nil {
		t.Fatal("an agent carrying an operator role was accepted")
	}
	good := base
	good.Subject = "sub-1"
	good.Groups = []string{"aaes-approvers"}
	good.Roles = []Role{RoleApprover}
	if err := good.Validate(); err != nil {
		t.Fatalf("a fully specified operator was refused: %v", err)
	}
}

// TestRoleDisplayTextKeepsTheRecordValueAndNamesTheManager pins both halves of
// the vocabulary change. The RoleSponsor RECORD value must not move: every
// existing directory record, group mapping, approval policy and sealed record
// carries the historical spelling "sponsor". What a person reads on a page, in
// a refusal or in the CLI is "manager". Deleting the display mapping fails
// this test, and so does renaming the wire value.
func TestRoleDisplayTextKeepsTheRecordValueAndNamesTheManager(t *testing.T) {
	if got := string(RoleSponsor); got != "sponsor" {
		t.Fatalf("RoleSponsor = %q, want the historical record value %q", got, "sponsor")
	}
	if got := RolesText([]Role{RoleApprover, RoleSponsor}); got != "approver,sponsor" {
		t.Fatalf("RolesText = %q, want the wire spelling %q", got, "approver,sponsor")
	}
	if got := RoleDisplayText(RoleSponsor); got != "manager" {
		t.Fatalf("RoleDisplayText(RoleSponsor) = %q, want %q", got, "manager")
	}
	if got := RoleDisplayText(RoleApprover); got != "approver" {
		t.Fatalf("RoleDisplayText(RoleApprover) = %q, want %q", got, "approver")
	}
	if got := RolesDisplayText([]Role{RoleApprover, RoleSponsor}); got != "approver,manager" {
		t.Fatalf("RolesDisplayText = %q, want %q", got, "approver,manager")
	}
	if got := RoleListDisplayText("approver,sponsor,auditor"); got != "approver,manager,auditor" {
		t.Fatalf("RoleListDisplayText = %q, want %q", got, "approver,manager,auditor")
	}
	if got := RoleListDisplayText(""); got != "" {
		t.Fatalf("RoleListDisplayText(%q) = %q, want the empty string", "", got)
	}
}
