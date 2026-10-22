package verifier

import (
	"github.com/aaes-ai/aaesverify/internal/types"
)

// The scoped full-export record checks of design section 4.8. They run only
// after the cryptographic phase passes: the offline verifier cannot infer
// that the producer ran its source admission rules, so it independently
// enforces exactly these scoped rules — receipt identity/parent (rule 1),
// approval identity and single-record validity (rule 2), state-dependent
// approver rules (rule 3), and approval history validity (rule 4). Receipt
// approval_id and approval ApprovalID are correlation keys only (rule 5): a
// pending or expired approval needs no decision entry and proves no
// authorization.

// checkReceiptsV4 enforces rule 1: receipt_id is nonempty and unique within
// the tenant export (across classes and parents), and each receipt's outer
// sequence/record_hash identifies exactly one decision entry PRECEDING the
// receipt, with the nested tenant, intent, record hash and grant agreeing
// with that parent. It returns the receipt_identity_and_parent label.
func checkReceiptsV4(exp *ExportFile, res *Result) string {
	fail := func(format string, args ...any) string {
		res.addError(format, args...)
		return labelFailed
	}
	type parentKey struct {
		sequence   uint64
		recordHash string
	}
	parents := make(map[parentKey]int, len(exp.Entries))
	for i, l := range exp.LeavesV4 {
		if l.Kind != lineEntry {
			continue
		}
		k := parentKey{l.Entry.Sequence, l.Entry.RecordHash}
		if _, dup := parents[k]; dup {
			return fail("decision entries %d and %d share sequence %d and record hash; a receipt parent must be unambiguous", parents[k], i, l.Entry.Sequence)
		}
		parents[k] = i
	}
	seen := make(map[string]int, len(exp.Receipts))
	for pos, l := range exp.LeavesV4 {
		if l.Kind != lineReceiptV4 {
			continue
		}
		r := l.Receipt
		id := *r.Receipt.ReceiptID // required-present on the wire
		if id == "" {
			return fail("receipt leaf %d: receipt_id is empty", pos)
		}
		if first, dup := seen[id]; dup {
			return fail("receipt leaf %d: receipt_id %q duplicates leaf %d; receipt ids are unique within the tenant export across every class and parent", pos, id, first)
		}
		seen[id] = pos
		pidx, ok := parents[parentKey{*r.Sequence, r.RecordHash}]
		if !ok {
			return fail("receipt leaf %d (%s): no decision entry names sequence %d and record hash %s; the receipt is an orphan", pos, id, *r.Sequence, r.RecordHash)
		}
		if pidx >= pos {
			return fail("receipt leaf %d (%s): the parent decision at leaf %d does not precede the receipt", pos, id, pidx)
		}
		parent := exp.LeavesV4[pidx].Entry
		if msg := receiptParentAgreementV4(r, parent); msg != "" {
			return fail("receipt leaf %d (%s): %s", pos, id, msg)
		}
	}
	return labelVerified
}

// receiptParentAgreementV4 checks the nested receipt against its parent
// decision: tenant, intent and record hash must equal the parent's, and a
// present grant_id must equal the parent's (an omitted grant_id stays the
// optional-empty wire case). A nested tenant disagreeing with the parent is
// the cross-tenant refusal.
func receiptParentAgreementV4(r *ReceiptLeafViewV4, parent *EntryView) string {
	if *r.Receipt.TenantID != parent.TenantID {
		return "nested tenant_id does not agree with the parent decision; cross-tenant receipts fail"
	}
	if *r.Receipt.IntentID != parent.IntentID {
		return "nested intent_id does not agree with the parent decision"
	}
	if *r.Receipt.RecordHash != parent.RecordHash {
		return "nested record_hash does not agree with the parent decision; rebinding fails"
	}
	if r.Receipt.GrantID != nil && *r.Receipt.GrantID != parent.GrantID {
		return "nested grant_id does not agree with the parent decision"
	}
	return ""
}

// checkApprovalsV4 enforces rules 2–4 over the approval leaves and returns
// the approval_source_history label. Source sequences are strictly increasing
// in file order, so grouping by ApprovalID preserves ascending order.
func checkApprovalsV4(exp *ExportFile, res *Result) string {
	ok := true
	var prevSource uint64
	groups := map[string][]int{}
	var order []string
	for pos, l := range exp.LeavesV4 {
		if l.Kind != lineApprovalV4 {
			continue
		}
		a := &l.Approval.Approval
		if !checkApprovalIdentityV4(exp, res, pos, a) {
			ok = false
		}
		if !checkApprovalStateV4(res, pos, a) {
			ok = false
		}
		if *l.Approval.SourceSequence <= prevSource {
			res.addError("approval leaf %d: source_sequence %d does not strictly increase over %d", pos, *l.Approval.SourceSequence, prevSource)
			ok = false
		}
		prevSource = *l.Approval.SourceSequence
		id := *a.ApprovalID
		if _, seenGroup := groups[id]; !seenGroup {
			order = append(order, id)
		}
		groups[id] = append(groups[id], pos)
	}
	for _, id := range order {
		if !checkApprovalHistoryGroupV4(exp, res, id, groups[id]) {
			ok = false
		}
	}
	if !ok {
		return labelFailed
	}
	return labelVerified
}

// checkApprovalIdentityV4 enforces rule 2's single-record validity: nonempty
// identifiers, nonzero creation and expiry with expiry after creation, the
// header tenant, and a persisted state — not_required (0) and every unknown
// value are invalid in a persisted approval leaf.
func checkApprovalIdentityV4(exp *ExportFile, res *Result, pos int, a *ApprovalV4) bool {
	ok := true
	// The required-present pointers are guaranteed non-nil by the wire decode.
	for _, id := range []struct {
		name  string
		value string
	}{
		{"ApprovalID", *a.ApprovalID},
		{"TenantID", *a.TenantID},
		{"TaskID", *a.TaskID},
		{"IntentID", *a.IntentID},
	} {
		if id.value == "" {
			res.addError("approval leaf %d: %s is empty", pos, id.name)
			ok = false
		}
	}
	if a.CreatedAt.IsZero() {
		res.addError("approval leaf %d: CreatedAt is zero", pos)
		ok = false
	}
	if a.ExpiresAt.IsZero() {
		res.addError("approval leaf %d: ExpiresAt is zero", pos)
		ok = false
	}
	if !a.CreatedAt.IsZero() && !a.ExpiresAt.IsZero() && !a.ExpiresAt.After(*a.CreatedAt) {
		res.addError("approval leaf %d: ExpiresAt is not after CreatedAt", pos)
		ok = false
	}
	if *a.TenantID != "" && *a.TenantID != exp.Header.TenantID {
		res.addError("approval leaf %d: tenant %q is not the export tenant %q", pos, *a.TenantID, exp.Header.TenantID)
		ok = false
	}
	if *a.State < types.ApprovalPending || *a.State > types.ApprovalExpired {
		res.addError("approval leaf %d: State %d (%s) is not a persisted approval state", pos, int(*a.State), a.State.String())
		ok = false
	}
	return ok
}
