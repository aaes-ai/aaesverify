package verifier

import (
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/types"
)

// Approval history validity (design section 4.8 rule 4): first record
// pending, successors preserve the raise facts, pending→pending only grows
// the manager set by at least one deciding human, and the decided states are
// terminal.

// v4TwoRecordHistory is a valid pending→granted history for ap-1.
func v4TwoRecordHistory(t *testing.T) *v4ExportBuilder {
	b := newV4Builder(t)
	granted := v4ApprovalGranted(b.specs[3].approval, 23, "alice", v4Base.Add(4*time.Hour))
	b.specs = append(b.specs, v4ApprovalSpec(granted))
	return b
}

func TestV4ApprovalHistoryRefusals(t *testing.T) {
	t.Run("first record not pending", func(t *testing.T) {
		b := newV4Builder(t)
		b.specs[3] = v4ApprovalSpec(v4ApprovalGranted(b.specs[3].approval, 17, "alice", v4Base.Add(4*time.Hour)))
		expectV4ApprovalFailure(t, b, "opens pending")
	})

	t.Run("successor after granted", func(t *testing.T) {
		b := v4TwoRecordHistory(t)
		next := v4ApprovalPending("ap-1", "tenant-a", 24, v4Base.Add(5*time.Hour))
		b.specs = append(b.specs, v4ApprovalSpec(next))
		expectV4ApprovalFailure(t, b, "terminal")
	})

	t.Run("successor after rejected", func(t *testing.T) {
		b := newV4Builder(t)
		rejected := v4ApprovalGranted(b.specs[3].approval, 23, "alice", v4Base.Add(4*time.Hour))
		*rejected.Approval.State = types.ApprovalRejected
		b.specs = append(b.specs, v4ApprovalSpec(rejected))
		next := v4ApprovalPending("ap-1", "tenant-a", 24, v4Base.Add(5*time.Hour))
		b.specs = append(b.specs, v4ApprovalSpec(next))
		expectV4ApprovalFailure(t, b, "terminal")
	})

	t.Run("successor after expired", func(t *testing.T) {
		b := newV4Builder(t)
		expired := v4ApprovalExpired(b.specs[3].approval, 23, v4Base.Add(5*time.Hour))
		b.specs = append(b.specs, v4ApprovalSpec(expired))
		next := v4ApprovalPending("ap-1", "tenant-a", 24, v4Base.Add(6*time.Hour))
		b.specs = append(b.specs, v4ApprovalSpec(next))
		expectV4ApprovalFailure(t, b, "terminal")
	})

	t.Run("same-managers pending to pending", func(t *testing.T) {
		b := newV4Builder(t)
		next := v4ApprovalPending("ap-1", "tenant-a", 24, v4Base.Add(5*time.Hour))
		b.specs = append(b.specs, v4ApprovalSpec(next))
		expectV4ApprovalFailure(t, b, "deciding human")
	})

	t.Run("manager set shrink", func(t *testing.T) {
		b := newV4Builder(t)
		b.specs[3].approval.Approval.RequesterManagers = []ManagerEntryV4{
			v4Manager("m1", types.KindHuman, types.ManagerAccountable, true),
			v4Manager("m2", types.KindHuman, types.ManagerApprover, false),
		}
		next := v4ApprovalPending("ap-1", "tenant-a", 24, v4Base.Add(5*time.Hour))
		next.Approval.RequesterManagers = []ManagerEntryV4{
			v4Manager("m1", types.KindHuman, types.ManagerAccountable, true),
		}
		b.specs = append(b.specs, v4ApprovalSpec(next))
		expectV4ApprovalFailure(t, b, "deciding human")
	})

	t.Run("manager entry altered", func(t *testing.T) {
		b := newV4Builder(t)
		b.specs[3].approval.Approval.RequesterManagers = []ManagerEntryV4{
			v4Manager("m1", types.KindHuman, types.ManagerAccountable, true),
		}
		next := v4ApprovalPending("ap-1", "tenant-a", 24, v4Base.Add(5*time.Hour))
		next.Approval.RequesterManagers = []ManagerEntryV4{
			v4Manager("m1", types.KindHuman, types.ManagerApprover, true), // role rewritten
			v4Manager("m2", types.KindHuman, types.ManagerApprover, false),
		}
		b.specs = append(b.specs, v4ApprovalSpec(next))
		expectV4ApprovalFailure(t, b, "deciding human")
	})

	t.Run("non-deciding growth: informed human", func(t *testing.T) {
		b := newV4Builder(t)
		next := v4ApprovalPending("ap-1", "tenant-a", 24, v4Base.Add(5*time.Hour))
		next.Approval.RequesterManagers = []ManagerEntryV4{
			v4Manager("m1", types.KindHuman, types.ManagerInformed, false),
		}
		b.specs = append(b.specs, v4ApprovalSpec(next))
		expectV4ApprovalFailure(t, b, "deciding human")
	})

	t.Run("non-human growth: agent manager", func(t *testing.T) {
		b := newV4Builder(t)
		next := v4ApprovalPending("ap-1", "tenant-a", 24, v4Base.Add(5*time.Hour))
		next.Approval.RequesterManagers = []ManagerEntryV4{
			v4Manager("bot", types.KindAgent, types.ManagerAccountable, false),
		}
		b.specs = append(b.specs, v4ApprovalSpec(next))
		expectV4ApprovalFailure(t, b, "deciding human")
	})
}

// TestV4ApprovalRaiseFacts pins every immutable raise fact: mutating each one
// on the granted successor must fail the history check.
func TestV4ApprovalRaiseFacts(t *testing.T) {
	cases := []struct {
		name string
		f    func(a *ApprovalV4)
	}{
		{"TenantID", func(a *ApprovalV4) { /* same tenant: identity rule covers cross-tenant */
			a.TenantID = v4str("tenant-a2")
		}},
		{"TaskID", func(a *ApprovalV4) { a.TaskID = v4str("task-2") }},
		{"RequestRecordID", func(a *ApprovalV4) { a.RequestRecordID = v4str("rr-9") }},
		{"IntentID", func(a *ApprovalV4) { a.IntentID = v4str("intent-2") }},
		{"Requester", func(a *ApprovalV4) { a.Requester = v4str("agent-2") }},
		{"InitiatedBy", func(a *ApprovalV4) { a.InitiatedBy = v4str("agent-2") }},
		{"RequesterSponsor", func(a *ApprovalV4) { a.RequesterSponsor = v4str("sponsor-9") }},
		{"RequesterModelProvider", func(a *ApprovalV4) { a.RequesterModelProvider = v4str("p") }},
		{"RequesterModelFamily", func(a *ApprovalV4) { a.RequesterModelFamily = v4str("f") }},
		{"RequesterModel", func(a *ApprovalV4) { a.RequesterModel = v4str("m") }},
		{"Sponsor", func(a *ApprovalV4) { a.Sponsor = v4str("sponsor-9") }},
		{"CreatedAt", func(a *ApprovalV4) { a.CreatedAt = v4timep(a.CreatedAt.Add(time.Second)) }},
		{"ExpiresAt", func(a *ApprovalV4) { a.ExpiresAt = v4timep(a.ExpiresAt.Add(time.Hour)) }},
		{"PayloadHash", func(a *ApprovalV4) { a.PayloadHash = v4str("ph-2") }},
		{"BundleHash", func(a *ApprovalV4) { a.BundleHash = v4str("bh-2") }},
		{"EngineVersion", func(a *ApprovalV4) { a.EngineVersion = v4str("ev-2") }},
		{"Action", func(a *ApprovalV4) { a.Action = v4str("read") }},
		{"ApprovalPolicyID", func(a *ApprovalV4) { a.ApprovalPolicyID = v4str("pol-9") }},
		{"RequesterManagersSource", func(a *ApprovalV4) {
			src := types.ManagerSourceSet
			a.RequesterManagersSource = &src
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := v4TwoRecordHistory(t)
			tc.f(&b.specs[4].approval.Approval)
			expectV4ApprovalFailure(t, b, "raise fact")
		})
	}
}

// TestV4ApprovalLegalTransitions exercises every legal transition to prevent
// over-refusal: pending→pending with deciding-human growth, pending→granted,
// pending→rejected, pending→expired, and independent groups per ApprovalID.
func TestV4ApprovalLegalTransitions(t *testing.T) {
	b := newV4Builder(t)
	pending := b.specs[3].approval

	// ap-1: pending → pending (manager growth adds a deciding human) → granted.
	pending.Approval.RequesterManagers = []ManagerEntryV4{
		v4Manager("m1", types.KindHuman, types.ManagerAccountable, true),
	}
	grown := v4ApprovalPendingGrowth(pending, 18, v4Base.Add(5*time.Hour), []ManagerEntryV4{
		v4Manager("m1", types.KindHuman, types.ManagerAccountable, true),
		v4Manager("m2", types.KindHuman, types.ManagerApprover, false),
	})
	granted := v4ApprovalGranted(grown, 19, "alice", v4Base.Add(6*time.Hour))
	b.specs = append(b.specs, v4ApprovalSpec(grown), v4ApprovalSpec(granted))

	// ap-2: pending → rejected.
	rejectBase := v4ApprovalPending("ap-2", "tenant-a", 30, v4Base.Add(3*time.Minute))
	rejected := v4ApprovalGranted(rejectBase, 31, "bob", v4Base.Add(7*time.Hour))
	rejectedState := types.ApprovalRejected
	rejected.Approval.State = &rejectedState
	b.specs = append(b.specs, v4ApprovalSpec(rejectBase), v4ApprovalSpec(rejected))

	// ap-3: pending → expired.
	expireBase := v4ApprovalPending("ap-3", "tenant-a", 40, v4Base.Add(4*time.Minute))
	expired := v4ApprovalExpired(expireBase, 41, v4Base.Add(8*time.Hour))
	b.specs = append(b.specs, v4ApprovalSpec(expireBase), v4ApprovalSpec(expired))

	doc := b.build()
	res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring(), ExpectedFinal: v4Pin(doc.head)})
	if !res.OK || res.ApprovalSourceHistory != labelVerified || res.ExpectedFinalHead != labelVerified {
		t.Fatalf("ok=%v approval=%q final=%q errors=%v", res.OK, res.ApprovalSourceHistory, res.ExpectedFinalHead, res.Errors)
	}
}

// TestV4ApprovalCorrelationOnly pins rule 5: a pending or expired approval
// needs no decision entry — the default fixture's approval references no
// entry and verifies; approval_id on a receipt is a correlation key, not an
// authorization check.
func TestV4ApprovalCorrelationOnly(t *testing.T) {
	b := newV4Builder(t)
	// The receipt names an approval id that resolves to the pending approval;
	// pending approvals are not proof that authorization occurred, and the
	// verifier checks correlation, not authorization.
	b.specs[2].receipt.Receipt.ApprovalID = v4str("ap-1")
	doc := b.build()
	res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
	if !res.OK {
		t.Fatalf("correlation-only export failed: %v", res.Errors)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "") {
		_ = res
	}
}
