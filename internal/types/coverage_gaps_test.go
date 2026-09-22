package types

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

// These tests close remaining statement coverage in the model package: every
// vocabulary String including the unknown spelling, every Validate refusal,
// and the work/approval/grant state machines. A String that folded an unknown
// value into a real name would be a lie in the one place a reader checks what
// was permitted.

func TestVocabularyStringsNameEveryValueAndRefuseUnknown(t *testing.T) {
	for _, tc := range []struct {
		got  string
		want string
	}{
		{WorkDraft.String(), "draft"},
		{WorkOpen.String(), "open"},
		{WorkClaimed.String(), "claimed"},
		{WorkBlocked.String(), "blocked"},
		{WorkCompleted.String(), "completed"},
		{WorkAbandoned.String(), "abandoned"},
		{WorkExpired.String(), "expired"},
		{WorkState(99).String(), "unknown(99)"},
		{ApprovalNotRequired.String(), "not_required"},
		{ApprovalPending.String(), "pending"},
		{ApprovalGranted.String(), "granted"},
		{ApprovalRejected.String(), "rejected"},
		{ApprovalExpired.String(), "expired"},
		{ApprovalState(99).String(), "unknown(99)"},
		{CustodyInline.String(), "inline"},
		{CustodyCustomerVault.String(), "customer_vault"},
		{CustodyIdentityFederation.String(), "identity_federation"},
		{CustodyPassThrough.String(), "pass_through"},
		{CustodyCustomerBroker.String(), "customer_broker"},
		{CustodyKind(99).String(), "unknown(99)"},
		{ConnHTTP.String(), "http"},
		{ConnMCP.String(), "mcp"},
		{ConnCLI.String(), "cli"},
		{ConnSQL.String(), "sql"},
		{ConnEmail.String(), "email"},
		{ConnTelephony.String(), "telephony"},
		{ConnBrowser.String(), "browser"},
		{ConnectorKind(99).String(), "unknown(99)"},
		{LocInline.String(), "inline"},
		{LocKMS.String(), "kms"},
		{LocIdP.String(), "idp"},
		{Location(99).String(), "unknown"},
		{InjectHeader.String(), "header"},
		{InjectQuery.String(), "query"},
		{InjectBody.String(), "body"},
		{InjectMCP.String(), "mcp"},
		{Injection(99).String(), "unknown"},
		{DataPublic.String(), "public"},
		{DataInternal.String(), "internal"},
		{DataPII.String(), "pii"},
		{DataPHI.String(), "phi"},
		{DataFinancial.String(), "financial"},
		{DataClassification(99).String(), "unknown"},
		{CapTool.String(), "tool"},
		{CapSkill.String(), "skill"},
		{KindHuman.String(), "human"},
		{KindAgent.String(), "agent"},
		{ManagerAccountable.String(), "accountable"},
		{ManagerApprover.String(), "approver"},
		{ManagerInformed.String(), "informed"},
		{ManagerRole(99).String(), "unknown(99)"},
		{ManagerSourceLegacy.String(), "legacy"},
		{ManagerSourceSingle.String(), "single"},
		{ManagerSourceSet.String(), "set"},
		{ManagerSource(99).String(), "unknown(99)"},
		{ManagerGateInherit.String(), "inherit"},
		{ManagerGateAny.String(), "any"},
		{ManagerGateAll.String(), "all"},
		{ManagerGateQuorum.String(), "quorum"},
		{ManagerGateOff.String(), "off"},
		{ManagerGate(99).String(), "unknown(99)"},
		{EffectDenied.String(), "denied"},
		{EffectMintedUnused.String(), "minted_unused"},
		{EffectExecuted.String(), "executed"},
		{EffectAuthorized.String(), "authorized"},
		{EffectClass(99).String(), "unknown(99)"},
		{R0RiskTier.String(), "R0"},
		{R4RiskTier.String(), "R4"},
		{RiskTierUnspecified.String(), "R?-1"},
		{RiskTier(99).String(), "R?99"},
		{DurationStanding.String(), "standing"},
		{RoleApprover.String(), "approver"},
		{RoleSponsor.String(), "sponsor"},
		{ModelSource("").String(), "unknown"},
		{ModelSourceRegistered.String(), "registered"},
	} {
		if tc.got != tc.want {
			t.Errorf("String() = %q, want %q", tc.got, tc.want)
		}
	}
}

func TestWorkStateMachineAndBudget(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Hour)
	w := Work{
		WorkID: "w1", TenantID: "t1", Sponsor: "human-1",
		State: WorkOpen, BudgetUSD: 100, CommittedUSD: 40, Deadline: deadline,
	}
	if w.Remaining() != 60 {
		t.Fatalf("Remaining() = %v, want 60", w.Remaining())
	}
	if !WorkOpen.AcceptsSpend() || !WorkClaimed.AcceptsSpend() || !WorkBlocked.AcceptsSpend() {
		t.Fatal("open, claimed and blocked must accept spend")
	}
	if WorkDraft.AcceptsSpend() || WorkCompleted.AcceptsSpend() {
		t.Fatal("draft and completed must not accept spend")
	}
	if !WorkCompleted.Terminal() || !WorkAbandoned.Terminal() || !WorkExpired.Terminal() {
		t.Fatal("completed, abandoned and expired are terminal")
	}
	if WorkOpen.Terminal() || WorkClaimed.Terminal() || WorkBlocked.Terminal() || WorkDraft.Terminal() {
		t.Fatal("non-terminal states reported as terminal")
	}
	if err := w.CanSpend(50, now); err != nil {
		t.Fatalf("a spend inside the remaining budget was refused: %v", err)
	}
	if err := w.CanSpend(61, now); err == nil || !strings.Contains(err.Error(), "remaining") {
		t.Fatalf("an over-budget spend was accepted: %v", err)
	}
	if err := w.CanSpend(-1, now); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("a negative spend was accepted: %v", err)
	}
	if err := w.CanSpend(1, deadline.Add(time.Second)); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("a spend after the deadline was accepted: %v", err)
	}
	closed := w
	closed.State = WorkCompleted
	if err := closed.CanSpend(1, now); err == nil || !strings.Contains(err.Error(), "completed") {
		t.Fatalf("a spend against completed work was accepted: %v", err)
	}
}

func TestWorkValidateRefusesUngovernableRecords(t *testing.T) {
	ok := Work{WorkID: "w1", TenantID: "t1", Sponsor: "human-1", BudgetUSD: 10, CommittedUSD: 1, Depth: 1}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a valid work was refused: %v", err)
	}
	raw, err := json.Marshal(ok)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round Work
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if round.WorkID != ok.WorkID || round.Sponsor != ok.Sponsor {
		t.Fatalf("round-trip lost identity: %+v", round)
	}

	for _, tc := range []struct {
		name string
		mut  func(*Work)
		want string
	}{
		{"no work id", func(w *Work) { w.WorkID = "" }, "WorkID"},
		{"no tenant", func(w *Work) { w.TenantID = "" }, "TenantID"},
		{"no sponsor", func(w *Work) { w.Sponsor = "" }, "accountable manager"},
		{"negative budget", func(w *Work) { w.BudgetUSD = -1 }, "negative budget"},
		{"negative committed", func(w *Work) { w.CommittedUSD = -1 }, "negative committed"},
		{"committed above budget", func(w *Work) { w.CommittedUSD = 20 }, "above its budget"},
		{"negative depth", func(w *Work) { w.Depth = -1 }, "delegation depth"},
		{"depth above cap", func(w *Work) { w.Depth = DefaultMaxDelegationDepth + 1 }, "cap is"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := ok
			tc.mut(&w)
			err := w.Validate()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestApprovalValidateRefusesUngovernableRecords(t *testing.T) {
	ok := Approval{
		ApprovalID: "apr-1", TenantID: "t1", WorkID: "w1", IntentID: "i1",
		Approver: "human-1", State: ApprovalGranted,
		ExpiresAt: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC),
		Action:    "read",
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a valid approval was refused: %v", err)
	}
	ok.RequesterManagers = SingleManagerSet("human-mgr", KindHuman)
	if err := ok.Validate(); err != nil {
		t.Fatalf("an approval with a sealed manager set was refused: %v", err)
	}

	for _, tc := range []struct {
		name string
		mut  func(*Approval)
		want string
	}{
		{"no approval id", func(a *Approval) { a.ApprovalID = "" }, "ApprovalID"},
		{"no tenant", func(a *Approval) { a.TenantID = "" }, "TenantID"},
		{"no work", func(a *Approval) { a.WorkID = "" }, "WorkID"},
		{"no approver", func(a *Approval) { a.Approver = "" }, "no approver"},
		{"no expiry", func(a *Approval) { a.ExpiresAt = time.Time{} }, "never expires"},
		{"unknown authority", func(a *Approval) { a.ApproverAuthority = ApprovalAuthority(9) }, "unknown approval authority"},
		{"invalid manager set", func(a *Approval) {
			a.RequesterManagers = ManagerSet{{ActorID: "risk-1", Kind: KindHuman, Role: ManagerApprover}}
		}, "no accountable manager"},
		{"unknown manager source", func(a *Approval) { a.RequesterManagersSource = ManagerSource(9) }, "unknown manager source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ok
			tc.mut(&a)
			err := a.Validate()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestEffectKeyIsStableAndRefusesEmptyParts(t *testing.T) {
	k := EffectKey{WorkID: "w1", StepKey: "send-confirm"}
	if err := k.Validate(); err != nil {
		t.Fatalf("a complete key was refused: %v", err)
	}
	if got := k.String(); got != "w1\x1fsend-confirm" {
		t.Fatalf("String() = %q, want the unit-separator form", got)
	}
	other := EffectKey{WorkID: "w1x", StepKey: "send-confirm"}
	if k.String() == other.String() {
		t.Fatal("two different keys rendered identically")
	}
	if err := (EffectKey{StepKey: "s"}).Validate(); err == nil || !strings.Contains(err.Error(), "WorkID") {
		t.Fatalf("a key with no WorkID was accepted: %v", err)
	}
	if err := (EffectKey{WorkID: "w1"}).Validate(); err == nil || !strings.Contains(err.Error(), "StepKey") {
		t.Fatalf("a key with no StepKey was accepted: %v", err)
	}
}

func TestGrantMaterialTTLAndValidity(t *testing.T) {
	issued := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	expires := issued.Add(5 * time.Minute)
	g := Grant{
		GrantID: "g1", ActorID: "agent-1", TenantID: "t1", Capability: "pay",
		Tier: R3RiskTier, TaskID: "w1", IssuedAt: issued, ExpiresAt: expires,
		SpendCapUSD: 10, NonTransferable: true, BudgetGrantID: "bg-1", Issuer: "key-1",
	}
	material := g.GrantMaterial()
	if len(material) != 12 {
		t.Fatalf("GrantMaterial has %d fields, want 12", len(material))
	}
	if material[0] != "g1" || material[4] != "R3" || material[10] != "bg-1" {
		t.Fatalf("GrantMaterial = %v", material)
	}
	if g.TTL() != 5*time.Minute {
		t.Fatalf("TTL = %s, want 5m", g.TTL())
	}
	if !g.Valid(issued.Add(time.Minute)) {
		t.Fatal("an in-window non-transferable grant is not valid")
	}
	if g.Valid(expires) || g.Valid(issued.Add(-time.Second)) {
		t.Fatal("a grant at or after expiry, or before issue, reported valid")
	}
	transferable := g
	transferable.NonTransferable = false
	if transferable.Valid(issued.Add(time.Minute)) {
		t.Fatal("a transferable grant reported valid")
	}
	anon := g
	anon.GrantID = ""
	if anon.Valid(issued.Add(time.Minute)) {
		t.Fatal("an unattributed grant reported valid")
	}
}

func TestActorManagersAndValidateGaps(t *testing.T) {
	declared := ActorRef{
		ActorID: "agent-1", TenantID: "t1", Kind: KindAgent, Sponsor: "human-1",
		Managers:       SingleManagerSet("human-lead", KindHuman),
		ManagersSource: ManagerSourceSet,
	}
	if got := declared.EffectiveManagers(); !got.Equal(declared.Managers) {
		t.Fatalf("a declared set was not returned as declared: %s", got.Describe())
	}
	if got := declared.EffectiveManagerSource(); got != ManagerSourceSet {
		t.Fatalf("source = %s, want set", got)
	}
	primary, ok := declared.PrimaryManager()
	if !ok || primary.ActorID != "human-lead" {
		t.Fatalf("PrimaryManager = %+v, %t", primary, ok)
	}

	human := ActorRef{ActorID: "h1", TenantID: "t1", Kind: KindHuman}
	if got := human.EffectiveManagers(); got != nil {
		t.Fatalf("a person with no sponsor read as managed: %s", got.Describe())
	}
	if got := human.EffectiveManagerSource(); got != ManagerSourceLegacy {
		t.Fatalf("an unmanaged actor's source = %s, want legacy", got)
	}

	if err := (ActorRef{}).Validate(); err == nil || !strings.Contains(err.Error(), "ActorID") {
		t.Fatalf("an empty actor was accepted: %v", err)
	}
	badSource := ActorRef{ActorID: "agent-1", TenantID: "t1", Kind: KindAgent, Sponsor: "h1", ManagersSource: ManagerSource(9)}
	if err := badSource.Validate(); !errors.Is(err, ErrManagerSource) {
		t.Fatalf("unknown manager source = %v, want ErrManagerSource", err)
	}
	self := ActorRef{ActorID: "agent-1", TenantID: "t1", Kind: KindAgent, Sponsor: "agent-1"}
	if err := self.Validate(); !errors.Is(err, ErrManagerSelf) {
		t.Fatalf("an agent sponsoring itself = %v, want ErrManagerSelf", err)
	}
	managedHuman := ActorRef{
		ActorID: "h1", TenantID: "t1", Kind: KindHuman,
		Managers: SingleManagerSet("other", KindHuman),
	}
	if err := managedHuman.Validate(); err == nil || !strings.Contains(err.Error(), "only an agent is managed") {
		t.Fatalf("a person carrying a manager set was accepted: %v", err)
	}
	score := ActorRef{ActorID: "agent-1", TenantID: "t1", Kind: KindAgent, Sponsor: "h1", TrustScore: 1.1}
	if err := score.Validate(); err == nil || !strings.Contains(err.Error(), "trust score") {
		t.Fatalf("an out-of-range trust score was accepted: %v", err)
	}
	ctrl := ActorRef{ActorID: "h1", TenantID: "t1", Kind: KindHuman, Groups: []string{"eng" + string(rune(7))}}
	if err := ctrl.Validate(); err == nil || !strings.Contains(err.Error(), "control character") {
		t.Fatalf("a group with a control character was accepted: %v", err)
	}
}

func TestManagerSetHelpersAndParse(t *testing.T) {
	if _, ok := ParseManagerRole("Accountable"); !ok {
		t.Fatal("ParseManagerRole refused Accountable")
	}
	if _, ok := ParseManagerRole("  APPROVER "); !ok {
		t.Fatal("ParseManagerRole refused a trimmed spelling")
	}
	if role, ok := ParseManagerRole("owner"); ok || role != ManagerAccountable {
		t.Fatalf("ParseManagerRole(unknown) = %s, %t; want accountable, false", role, ok)
	}
	if err := ManagerSource(9).Validate(); !errors.Is(err, ErrManagerSource) {
		t.Fatalf("unknown source Validate = %v", err)
	}

	if got := (ManagerSet(nil)).Copy(); got != nil {
		t.Fatalf("Copy of nil = %v, want nil", got)
	}
	if err := (ManagerSet(nil)).Validate("agent-1"); !errors.Is(err, ErrManagerNoAccountable) {
		t.Fatalf("empty set Validate = %v, want ErrManagerNoAccountable", err)
	}
	if err := (ManagerEntry{}).Validate("agent-1"); !errors.Is(err, ErrManagerKind) {
		t.Fatalf("an entry with no id = %v, want ErrManagerKind", err)
	}
	if err := (ManagerEntry{ActorID: "h1", Kind: ActorKind(9), Role: ManagerAccountable}).Validate("agent-1"); !errors.Is(err, ErrManagerKind) {
		t.Fatalf("unknown kind = %v, want ErrManagerKind", err)
	}

	set := ManagerSet{
		{ActorID: "lead-1", Kind: KindHuman, Role: ManagerAccountable, Primary: true},
		{ActorID: "watch-1", Kind: KindHuman, Role: ManagerInformed},
	}
	informed := set.Informed()
	if len(informed) != 1 || informed[0].ActorID != "watch-1" {
		t.Fatalf("Informed = %s", informed.Describe())
	}
	if got := set.Describe(); !strings.Contains(got, "1:lead-1(human,accountable,primary)") || !strings.Contains(got, "informed") {
		t.Fatalf("Describe = %q", got)
	}
	if got := (ManagerSet(nil)).Describe(); got != "no managers" {
		t.Fatalf("empty Describe = %q", got)
	}
	none, ok := (ManagerSet{{ActorID: "watch-1", Kind: KindHuman, Role: ManagerInformed}}).Primary()
	if ok || none.ActorID != "" {
		t.Fatalf("Primary of an informed-only set = %+v, %t", none, ok)
	}
	if got := SingleManagerSet("  ", KindHuman); got != nil {
		t.Fatalf("SingleManagerSet of whitespace = %s", got.Describe())
	}
}

func TestRoleCopySortAndEmptyRenderings(t *testing.T) {
	if got := CopyRoles(nil); got != nil {
		t.Fatalf("CopyRoles(nil) = %v", got)
	}
	src := []Role{RoleAdmin, RoleApprover}
	copied := CopyRoles(src)
	copied[0] = RoleAuditor
	if src[0] != RoleAdmin {
		t.Fatal("CopyRoles shared a backing array")
	}
	if RolesText(nil) != "none" || RolesDisplayText(nil) != "none" {
		t.Fatal("an empty role list does not render as none")
	}
	mixed := []Role{Role("zzz"), RoleAdmin, Role("aaa"), RoleApprover}
	SortRoles(mixed)
	if mixed[0] != RoleApprover || mixed[1] != RoleAdmin || mixed[2] != Role("aaa") || mixed[3] != Role("zzz") {
		t.Fatalf("SortRoles mixed known and unknown = %v", mixed)
	}
	if _, err := ParseRoleList([]string{"approver", "not-a-role"}); err == nil {
		t.Fatal("ParseRoleList accepted an unknown role")
	}
}

func TestDelegationContractRemainingRefusals(t *testing.T) {
	ok := DelegationContract{
		ContractID: "c1", TenantID: "t1", FromActor: "human-1", ToActor: "agent-1",
		Sponsor: "human-1", BudgetUSD: 10, Depth: 1,
	}
	for _, tc := range []struct {
		name string
		mut  func(*DelegationContract)
		want string
	}{
		{"no contract id", func(c *DelegationContract) { c.ContractID = "" }, "ContractID"},
		{"no from", func(c *DelegationContract) { c.FromActor = "" }, "FromActor"},
		{"no to", func(c *DelegationContract) { c.ToActor = "" }, "ToActor"},
		{"no tenant", func(c *DelegationContract) { c.TenantID = "" }, "TenantID"},
		{"no sponsor", func(c *DelegationContract) { c.Sponsor = "" }, "manager who remains accountable"},
		{"depth above cap", func(c *DelegationContract) { c.Depth = DefaultMaxDelegationDepth + 1 }, "exceeds cap"},
		{"negative infinity", func(c *DelegationContract) { c.BudgetUSD = math.Inf(-1) }, "non-finite"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ok
			tc.mut(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestCapabilityValidateAndSecretRef(t *testing.T) {
	skill := Capability{CapabilityID: "how", Version: "1.0.0", Kind: CapSkill, RiskTier: R0RiskTier, Owner: "ops"}
	if err := skill.Validate(); err != nil {
		t.Fatalf("a public skill was refused: %v", err)
	}
	if skill.IsCredentialed() {
		t.Fatal("a skill with no secret is credentialed")
	}
	cred := skill
	cred.SecretRefID = "sec_1"
	cred.InjectName = "Authorization"
	if !cred.IsCredentialed() {
		t.Fatal("a capability with a secret is not credentialed")
	}
	if err := cred.Validate(); err != nil {
		t.Fatalf("a credentialed skill was refused: %v", err)
	}

	for _, tc := range []struct {
		name string
		mut  func(*Capability)
		want string
	}{
		{"no id", func(c *Capability) { c.CapabilityID = "" }, "CapabilityID"},
		{"no version", func(c *Capability) { c.Version = "" }, "Version"},
		{"no owner", func(c *Capability) { c.Owner = "" }, "accountable owner"},
		{"invalid tier", func(c *Capability) { c.RiskTier = RiskTier(9) }, "invalid risk tier"},
		{"unknown custody", func(c *Capability) { c.Custody = CustodyKind(99) }, "unknown custody"},
		{"secret without inject", func(c *Capability) { c.SecretRefID = "sec_1"; c.InjectName = "" }, "no injection point"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := skill
			tc.mut(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not contain %q", err, tc.want)
			}
		})
	}

	tool := Capability{
		CapabilityID: "pay", Version: "1.0.0", Kind: CapTool, RiskTier: R2RiskTier, Owner: "ops",
		Method: "POST", EgressAllowlist: []string{"rail.test"}, Endpoint: "https://rail.test/v1",
	}
	if err := tool.Validate(); err != nil {
		t.Fatalf("an R2 tool was refused: %v", err)
	}
	noEndpoint := tool
	noEndpoint.Endpoint = ""
	if err := noEndpoint.Validate(); err == nil || !strings.Contains(err.Error(), "without an endpoint") {
		t.Fatalf("an R2 tool with no endpoint was accepted: %v", err)
	}
	emptyMethod := tool
	emptyMethod.Method = ""
	if err := emptyMethod.Validate(); err == nil || !strings.Contains(err.Error(), "no usable registered operation") {
		t.Fatalf("an R2 tool with no method was accepted: %v", err)
	}
	longMethod := tool
	longMethod.Method = strings.Repeat("P", 65)
	if err := longMethod.Validate(); err == nil || !strings.Contains(err.Error(), "no usable registered operation") {
		t.Fatalf("an over-long method was accepted: %v", err)
	}
	spaceMethod := tool
	spaceMethod.Method = "PO ST"
	if err := spaceMethod.Validate(); err == nil || !strings.Contains(err.Error(), "no usable registered operation") {
		t.Fatalf("a method with a space was accepted: %v", err)
	}
	noScheme := tool
	noScheme.Endpoint = "rail.test/v1"
	noScheme.EgressAllowlist = []string{"rail.test"}
	if err := noScheme.Validate(); err == nil || !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("a relative endpoint was accepted: %v", err)
	}
	noHost := tool
	noHost.Endpoint = "https://"
	if err := noHost.Validate(); err == nil || !strings.Contains(err.Error(), "no host") {
		t.Fatalf("an endpoint with no host was accepted: %v", err)
	}
	unparseable := tool
	unparseable.Endpoint = "https://["
	if err := unparseable.Validate(); err == nil || !strings.Contains(err.Error(), "unparseable") {
		t.Fatalf("an unparseable endpoint was accepted: %v", err)
	}
	notAllowlisted := tool
	notAllowlisted.EgressAllowlist = []string{"other.test"}
	if err := notAllowlisted.Validate(); err == nil || !strings.Contains(err.Error(), "not in its own egress allowlist") {
		t.Fatalf("an endpoint outside its allowlist was accepted: %v", err)
	}
	_, err := tool.EndpointAuthority()
	if err != nil {
		t.Fatalf("EndpointAuthority of a valid tool: %v", err)
	}
	if _, err := (Capability{CapabilityID: "x"}).EndpointAuthority(); err == nil || !strings.Contains(err.Error(), "no endpoint") {
		t.Fatalf("EndpointAuthority with no endpoint: %v", err)
	}

	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	ref := SecretRef{SecretRefID: "sec_1", TenantID: "t1", Name: "rail", Location: LocInline, ExpiresAt: now.Add(time.Hour)}
	if err := ref.Validate(); err != nil {
		t.Fatalf("a valid secret ref was refused: %v", err)
	}
	if ref.Expired(now) || !ref.Expired(now.Add(2*time.Hour)) {
		t.Fatal("Expired disagrees with the window")
	}
	if (SecretRef{}).Expired(now) {
		t.Fatal("a secret with no expiry reads as expired")
	}
	if err := (SecretRef{SecretRefID: "sec_1"}).Validate(); err == nil || !strings.Contains(err.Error(), "SecretRefID") {
		t.Fatalf("an incomplete secret ref was accepted: %v", err)
	}
	kms := SecretRef{SecretRefID: "sec_1", TenantID: "t1", Name: "rail", Location: LocKMS}
	if err := kms.Validate(); err == nil || !strings.Contains(err.Error(), "no handle") {
		t.Fatalf("a KMS ref with no handle was accepted: %v", err)
	}
	kms.Handle = "arn:example"
	if err := kms.Validate(); err != nil {
		t.Fatalf("a KMS ref with a handle was refused: %v", err)
	}
}

func TestModelIdentityWhitespaceAndEmptyLevel(t *testing.T) {
	padded := ModelRef{Provider: " example", Family: "family", Model: "model-1", Source: ModelSourceRegistered}
	if err := padded.Validate(); err == nil || !strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("a padded provider was accepted: %v", err)
	}
	if got := UnknownModel().Identity(); got != "" {
		t.Fatalf("unknown Identity() = %q", got)
	}
	if err := validateModelLevel("Provider", ""); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("validateModelLevel empty = %v", err)
	}
}

func TestApprovalPolicyIndependenceAndQuorumDescribe(t *testing.T) {
	p := ApprovalPolicy{
		Required: 2, Classes: []ApproverClass{ApproverHuman}, MinHumans: 1,
		IndependentOf: []string{IndependenceRequester, IndependenceSponsor},
		ManagerGate:   ManagerGateQuorum, ManagerQuorum: 2,
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("a valid quorum policy was refused: %v", err)
	}
	if !p.RequiresIndependence(IndependenceRequester) || !p.RequiresIndependence(IndependenceSponsor) {
		t.Fatal("RequiresIndependence missed a declared role")
	}
	if p.RequiresIndependence("whoever") {
		t.Fatal("RequiresIndependence accepted an unknown role")
	}
	if !strings.Contains(p.Describe(), "manager_gate=quorum") || !strings.Contains(p.Describe(), "manager_quorum=2") {
		t.Fatalf("Describe of a quorum gate = %q", p.Describe())
	}
	off := ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverHuman}, ManagerGate: ManagerGateOff}
	if got := off.ManagerRequirement(3); got != 0 {
		t.Fatalf("ManagerRequirement(off) = %d, want 0", got)
	}
	if got := (ApprovalPolicy{}).ManagerRequirement(1); got != 0 {
		t.Fatalf("inherit over a one-manager set requires %d, want 0", got)
	}
	anyGate := ApprovalPolicy{Required: 1, Classes: []ApproverClass{ApproverHuman}, ManagerGate: ManagerGateAny}
	if got := anyGate.ManagerRequirement(0); got != 1 {
		t.Fatalf("ManagerRequirement(any, empty) = %d, want 1", got)
	}
}

func TestCanSpendRefusesANonFiniteBudget(t *testing.T) {
	w := Work{WorkID: "w-inf", State: WorkOpen, BudgetUSD: math.Inf(1)}
	if err := w.CanSpend(1, time.Time{}); err == nil || !strings.Contains(err.Error(), "non-finite") {
		t.Fatalf("infinite budget: %v", err)
	}
}
