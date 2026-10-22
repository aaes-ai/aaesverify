package verifier

import (
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/types"
)

// The section 4.8 scoped record checks: every rule gets a failing case, and
// the legal transitions get positive controls so a universally rejected
// fixture cannot masquerade as refusal coverage (section 9.5).

// expectV4ReceiptFailure asserts the receipt identity/parent check failed
// while the cryptographic phase passed.
func expectV4ReceiptFailure(t *testing.T, b *v4ExportBuilder, frag string) {
	t.Helper()
	doc := b.build()
	res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
	if res.ReceiptIdentityAndParent != labelFailed {
		t.Fatalf("receipt_identity_and_parent = %q, want failed (errors %v)", res.ReceiptIdentityAndParent, res.Errors)
	}
	if res.OK {
		t.Fatal("export passed")
	}
	if frag != "" && !strings.Contains(strings.Join(res.Errors, " "), frag) {
		t.Fatalf("errors %v do not name %q", res.Errors, frag)
	}
}

func expectV4ApprovalFailure(t *testing.T, b *v4ExportBuilder, frag string) {
	t.Helper()
	doc := b.build()
	res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
	if res.ApprovalSourceHistory != labelFailed {
		t.Fatalf("approval_source_history = %q, want failed (errors %v)", res.ApprovalSourceHistory, res.Errors)
	}
	if res.OK {
		t.Fatal("export passed")
	}
	if frag != "" && !strings.Contains(strings.Join(res.Errors, " "), frag) {
		t.Fatalf("errors %v do not name %q", res.Errors, frag)
	}
}

func TestV4ReceiptIdentityAndParent(t *testing.T) {
	t.Run("duplicate receipt id across classes and parents", func(t *testing.T) {
		b := newV4Builder(t)
		dup := v4ReceiptLeaf(*b.specs[0].entry, "rc-1", types.EffectDenied, v4Base.Add(6*time.Minute))
		b.specs = append(b.specs, v4ReceiptSpec(dup))
		expectV4ReceiptFailure(t, b, "duplicates")
	})
	t.Run("empty receipt id", func(t *testing.T) {
		b := newV4Builder(t)
		b.specs[2].receipt.Receipt.ReceiptID = v4str("")
		expectV4ReceiptFailure(t, b, "receipt_id is empty")
	})
	t.Run("orphan receipt", func(t *testing.T) {
		b := newV4Builder(t)
		b.specs[2].receipt.Sequence = v4uintp(99)
		b.specs[2].receipt.RecordHash = "ff00"
		expectV4ReceiptFailure(t, b, "orphan")
	})
	t.Run("parent after receipt", func(t *testing.T) {
		b := newV4Builder(t)
		// receipt bound to the SECOND entry, placed before it
		b.specs = []v4Spec{b.specs[0], b.specs[2], b.specs[1], b.specs[3]}
		expectV4ReceiptFailure(t, b, "does not precede")
	})
	t.Run("cross-tenant receipt", func(t *testing.T) {
		b := newV4Builder(t)
		b.specs[2].receipt.Receipt.TenantID = v4str("tenant-b")
		expectV4ReceiptFailure(t, b, "cross-tenant")
	})
	t.Run("intent mismatch", func(t *testing.T) {
		b := newV4Builder(t)
		b.specs[2].receipt.Receipt.IntentID = v4str("intent-other")
		expectV4ReceiptFailure(t, b, "intent_id")
	})
	t.Run("record hash rebinding", func(t *testing.T) {
		b := newV4Builder(t)
		b.specs[2].receipt.Receipt.RecordHash = v4str("rebound")
		expectV4ReceiptFailure(t, b, "record_hash")
	})
	t.Run("grant mismatch", func(t *testing.T) {
		b := newV4Builder(t)
		b.specs[2].receipt.Receipt.GrantID = v4str("grant-other")
		expectV4ReceiptFailure(t, b, "grant_id")
	})
	t.Run("two execution claims pass identity but execution stays not_checked", func(t *testing.T) {
		// The design's worked example: distinct ids, same valid parent,
		// matching bindings — the offline identity check passes and the
		// execution/lifecycle disclosure stays not_checked.
		b := newV4Builder(t)
		second := v4ReceiptLeaf(*b.specs[1].entry, "rc-2", types.EffectExecuted, v4Base.Add(6*time.Minute))
		b.specs = append(b.specs, v4ReceiptSpec(second))
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if !res.OK || res.ReceiptIdentityAndParent != labelVerified {
			t.Fatalf("ok=%v receipt label=%q errors=%v", res.OK, res.ReceiptIdentityAndParent, res.Errors)
		}
		if res.ReceiptExecutionValidity != labelNotChecked {
			t.Fatalf("receipt_execution_validity = %q, want not_checked", res.ReceiptExecutionValidity)
		}
	})
}

// TestV4ReceiptAmbiguousParent unit-tests the ambiguity guard directly: a
// full export cannot reach it (the chain check requires strictly increasing
// sequences first), so the guard is exercised on a hand-built ExportFile.
func TestV4ReceiptAmbiguousParent(t *testing.T) {
	e := v4Entry("tenant-a", 1, v4Base)
	entryLeaf := LeafV4{Kind: lineEntry, Entry: &e}
	receipt := v4ReceiptLeaf(e, "rc-1", types.EffectExecuted, v4Base.Add(time.Minute))
	exp := &ExportFile{
		Header:   HeaderView{TenantID: "tenant-a"},
		LeavesV4: []LeafV4{entryLeaf, entryLeaf, {Kind: lineReceiptV4, Receipt: receipt}},
	}
	res := &Result{}
	if got := checkReceiptsV4(exp, res); got != labelFailed {
		t.Fatalf("ambiguous parent = %q, want failed", got)
	}
	if !strings.Contains(strings.Join(res.Errors, " "), "unambiguous") {
		t.Fatalf("errors = %v", res.Errors)
	}
}

func TestV4ApprovalIdentity(t *testing.T) {
	mutate := []struct {
		name string
		f    func(a *ApprovalV4)
		frag string
	}{
		{"state not_required refused", func(a *ApprovalV4) { *a.State = types.ApprovalNotRequired }, "not a persisted approval state"},
		{"empty ApprovalID", func(a *ApprovalV4) { a.ApprovalID = v4str("") }, "ApprovalID is empty"},
		{"empty TenantID", func(a *ApprovalV4) { a.TenantID = v4str("") }, "TenantID is empty"},
		{"empty TaskID", func(a *ApprovalV4) { a.TaskID = v4str("") }, "TaskID is empty"},
		{"empty IntentID", func(a *ApprovalV4) { a.IntentID = v4str("") }, "IntentID is empty"},
		{"zero CreatedAt", func(a *ApprovalV4) { a.CreatedAt = v4timep(time.Time{}) }, "CreatedAt is zero"},
		{"zero ExpiresAt", func(a *ApprovalV4) { a.ExpiresAt = v4timep(time.Time{}) }, "ExpiresAt is zero"},
		{"expiry at creation", func(a *ApprovalV4) { a.ExpiresAt = a.CreatedAt }, "not after CreatedAt"},
		{"expiry before creation", func(a *ApprovalV4) { a.ExpiresAt = v4timep(a.CreatedAt.Add(-time.Hour)) }, "not after CreatedAt"},
		{"cross-tenant approval", func(a *ApprovalV4) { a.TenantID = v4str("tenant-b") }, "not the export tenant"},
	}
	for _, tc := range mutate {
		t.Run(tc.name, func(t *testing.T) {
			b := newV4Builder(t)
			tc.f(&b.specs[3].approval.Approval)
			expectV4ApprovalFailure(t, b, tc.frag)
		})
	}
	t.Run("source sequences must strictly increase", func(t *testing.T) {
		b := newV4Builder(t)
		older := v4ApprovalPending("ap-2", "tenant-a", 5, v4Base.Add(7*time.Minute))
		b.specs = append(b.specs, v4ApprovalSpec(older))
		expectV4ApprovalFailure(t, b, "strictly increase")
	})
}

func TestV4ApprovalStateDependent(t *testing.T) {
	granted := func() *v4ExportBuilder {
		b := newV4Builder(t)
		b.specs[3] = v4ApprovalSpec(v4ApprovalGranted(b.specs[3].approval, 17, "alice", v4Base.Add(4*time.Hour)))
		return b
	}
	cases := []struct {
		name string
		b    func() *v4ExportBuilder
		frag string
	}{
		{"granted with empty approver", func() *v4ExportBuilder {
			b := granted()
			b.specs[3].approval.Approval.Approver = v4str("")
			return b
		}, "nonempty Approver"},
		{"granted with zero decision time", func() *v4ExportBuilder {
			b := granted()
			b.specs[3].approval.Approval.DecidedAt = v4timep(time.Time{})
			return b
		}, "nonzero DecidedAt"},
		{"decision after expiry", func() *v4ExportBuilder {
			b := granted()
			b.specs[3].approval.Approval.DecidedAt = v4timep(b.specs[3].approval.Approval.ExpiresAt.Add(time.Hour))
			return b
		}, "after ExpiresAt"},
		{"pending with approver set", func() *v4ExportBuilder {
			b := newV4Builder(t)
			b.specs[3].approval.Approval.Approver = v4str("alice")
			return b
		}, "empty Approver"},
		{"pending with decision time", func() *v4ExportBuilder {
			b := newV4Builder(t)
			b.specs[3].approval.Approval.DecidedAt = v4timep(v4Base.Add(4 * time.Hour))
			return b
		}, "zero DecidedAt"},
		{"expired with approver set", func() *v4ExportBuilder {
			b := newV4Builder(t)
			a := &b.specs[3].approval.Approval
			*a.State = types.ApprovalExpired
			a.Approver = v4str("alice")
			return b
		}, "empty Approver"},
		{"agent approver without registered model source", func() *v4ExportBuilder {
			b := granted()
			a := &b.specs[3].approval.Approval
			*a.ApproverKind = types.ApproverAgent
			a.ApproverModelProvider = v4str("provider")
			a.ApproverModelFamily = v4str("family")
			a.ApproverModel = v4str("model")
			a.ApproverModelSource = v4str("unknown")
			return b
		}, "registered"},
		{"agent approver with incomplete model identity", func() *v4ExportBuilder {
			b := granted()
			a := &b.specs[3].approval.Approval
			*a.ApproverKind = types.ApproverAgent
			a.ApproverModelSource = v4str("registered")
			return b
		}, "model identity"},
		{"non-agent with model identity", func() *v4ExportBuilder {
			b := granted()
			b.specs[3].approval.Approval.ApproverModelProvider = v4str("provider")
			return b
		}, "non-agent"},
		{"non-agent with approver sponsor", func() *v4ExportBuilder {
			b := granted()
			b.specs[3].approval.Approval.ApproverSponsor = v4str("sponsor-1")
			return b
		}, "ApproverSponsor"},
		{"non-agent with model source", func() *v4ExportBuilder {
			b := granted()
			b.specs[3].approval.Approval.ApproverModelSource = v4str("registered")
			return b
		}, "ApproverModelSource"},
		{"unknown action", func() *v4ExportBuilder {
			b := newV4Builder(t)
			b.specs[3].approval.Approval.Action = v4str("nuke")
			return b
		}, "action vocabulary"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectV4ApprovalFailure(t, tc.b(), tc.frag)
		})
	}
	t.Run("valid agent approver accepted", func(t *testing.T) {
		b := newV4Builder(t)
		granted := v4ApprovalGranted(b.specs[3].approval, 23, "agent-alice", v4Base.Add(4*time.Hour))
		a := &granted.Approval
		agentKind := types.ApproverAgent
		a.ApproverKind = &agentKind
		a.ApproverModelProvider = v4str("provider")
		a.ApproverModelFamily = v4str("family")
		a.ApproverModel = v4str("model")
		a.ApproverModelSource = v4str("registered")
		a.ApproverSponsor = v4str("sponsor-1")
		b.specs = append(b.specs, v4ApprovalSpec(granted))
		doc := b.build()
		res := verifyV4(t, doc.text, VerifyOptions{Keyring: doc.signing.keyring()})
		if !res.OK || res.ApprovalSourceHistory != labelVerified {
			t.Fatalf("ok=%v label=%q errors=%v", res.OK, res.ApprovalSourceHistory, res.Errors)
		}
	})
}
