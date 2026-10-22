package verifier

import (
	"time"

	"github.com/aaes-ai/aaesverify/internal/types"
)

// The state-dependent approver rules (design section 4.8 rule 3) and the
// approval history validity rules (rule 4).

// checkApprovalStateV4 enforces rule 3 on one record: granted and rejected
// records carry a nonempty Approver and a nonzero DecidedAt not after expiry;
// pending and expired records carry an empty Approver and a zero DecidedAt.
// An agent approver requires a complete registered model identity; a
// non-agent carries no model identity and no ApproverSponsor; a present
// Action must be in the closed action vocabulary.
func checkApprovalStateV4(res *Result, pos int, a *ApprovalV4) bool {
	ok := true
	switch *a.State {
	case types.ApprovalGranted, types.ApprovalRejected:
		if *a.Approver == "" {
			res.addError("approval leaf %d: a %s record requires a nonempty Approver", pos, a.State.String())
			ok = false
		}
		if a.DecidedAt.IsZero() {
			res.addError("approval leaf %d: a %s record requires a nonzero DecidedAt", pos, a.State.String())
			ok = false
		} else if !a.ExpiresAt.IsZero() && a.DecidedAt.After(*a.ExpiresAt) {
			res.addError("approval leaf %d: DecidedAt is after ExpiresAt", pos)
			ok = false
		}
	case types.ApprovalPending, types.ApprovalExpired:
		if *a.Approver != "" {
			res.addError("approval leaf %d: a %s record must carry an empty Approver", pos, a.State.String())
			ok = false
		}
		if !a.DecidedAt.IsZero() {
			res.addError("approval leaf %d: a %s record must carry a zero DecidedAt", pos, a.State.String())
			ok = false
		}
	}
	if !checkApproverModelIdentityV4(res, pos, a) {
		ok = false
	}
	if a.Action != nil {
		if _, known := types.ParseAction(*a.Action); !known {
			res.addError("approval leaf %d: Action %q is outside the closed action vocabulary", pos, *a.Action)
			ok = false
		}
	}
	return ok
}

// checkApproverModelIdentityV4 enforces the approver identity rules: an agent
// approver carries a complete model provider/family/model registered in the
// directory; a non-agent carries none of that identity, no ApproverSponsor
// and no ApproverModelSource member at all.
func checkApproverModelIdentityV4(res *Result, pos int, a *ApprovalV4) bool {
	if *a.ApproverKind == types.ApproverAgent {
		ok := true
		for _, m := range []struct {
			name string
			p    *string
		}{
			{"ApproverModelProvider", a.ApproverModelProvider},
			{"ApproverModelFamily", a.ApproverModelFamily},
			{"ApproverModel", a.ApproverModel},
		} {
			if m.p == nil || *m.p == "" {
				res.addError("approval leaf %d: an agent approver requires a complete registered model identity; %s is missing", pos, m.name)
				ok = false
			}
		}
		if a.ApproverModelSource == nil || *a.ApproverModelSource != "registered" {
			res.addError("approval leaf %d: an agent approver requires ApproverModelSource \"registered\"", pos)
			ok = false
		}
		return ok
	}
	if a.ApproverModelProvider != nil || a.ApproverModelFamily != nil || a.ApproverModel != nil {
		res.addError("approval leaf %d: a non-agent approver must not carry agent model identity", pos)
		return false
	}
	if a.ApproverModelSource != nil {
		res.addError("approval leaf %d: a non-agent approver must not carry ApproverModelSource", pos)
		return false
	}
	if a.ApproverSponsor != nil {
		res.addError("approval leaf %d: a non-agent approver must not carry ApproverSponsor", pos)
		return false
	}
	return true
}

// checkApprovalHistoryV4 enforces rule 4 on one ApprovalID group, in
// ascending source_sequence order: the first record is pending, every
// successor preserves the raise facts, pending→pending only grows the manager
// set with at least one added deciding human, and granted, rejected and
// expired are terminal.
func checkApprovalHistoryGroupV4(exp *ExportFile, res *Result, id string, positions []int) bool {
	ok := true
	first := &exp.LeavesV4[positions[0]].Approval.Approval
	if *first.State != types.ApprovalPending {
		res.addError("approval %q: the first record (leaf %d) is %s; an approval history opens pending", id, positions[0], first.State.String())
		ok = false
	}
	for k := 1; k < len(positions); k++ {
		prev := &exp.LeavesV4[positions[k-1]].Approval.Approval
		cur := &exp.LeavesV4[positions[k]].Approval.Approval
		pos := positions[k]
		if *prev.State != types.ApprovalPending {
			res.addError("approval %q: leaf %d succeeds a %s record; granted, rejected and expired are terminal", id, pos, prev.State.String())
			ok = false
			continue
		}
		if field := raiseFactChangeV4(prev, cur); field != "" {
			res.addError("approval %q: leaf %d alters raise fact %s; successors preserve the raise facts", id, pos, field)
			ok = false
		}
		if *cur.State == types.ApprovalPending && !managerSetGrowthV4(prev.RequesterManagers, cur.RequesterManagers) {
			res.addError("approval %q: leaf %d stays pending without growing the manager set by at least one deciding human", id, pos)
			ok = false
		}
	}
	return ok
}

// raiseFactChangeV4 names the first raise fact a successor altered, or "".
// The raise facts are: tenant, task, request record, intent, requester,
// initiator, requester sponsor/model identity, sponsor, creation, expiry,
// payload hash, bundle hash, engine version, action, approval policy, and
// manager-set source.
func raiseFactChangeV4(prev, cur *ApprovalV4) string {
	for _, f := range []struct {
		name string
		a, b *string
	}{
		{"TenantID", prev.TenantID, cur.TenantID},
		{"TaskID", prev.TaskID, cur.TaskID},
		{"RequestRecordID", prev.RequestRecordID, cur.RequestRecordID},
		{"IntentID", prev.IntentID, cur.IntentID},
		{"Requester", prev.Requester, cur.Requester},
		{"InitiatedBy", prev.InitiatedBy, cur.InitiatedBy},
		{"RequesterSponsor", prev.RequesterSponsor, cur.RequesterSponsor},
		{"RequesterModelProvider", prev.RequesterModelProvider, cur.RequesterModelProvider},
		{"RequesterModelFamily", prev.RequesterModelFamily, cur.RequesterModelFamily},
		{"RequesterModel", prev.RequesterModel, cur.RequesterModel},
		{"Sponsor", prev.Sponsor, cur.Sponsor},
		{"PayloadHash", prev.PayloadHash, cur.PayloadHash},
		{"BundleHash", prev.BundleHash, cur.BundleHash},
		{"EngineVersion", prev.EngineVersion, cur.EngineVersion},
		{"Action", prev.Action, cur.Action},
		{"ApprovalPolicyID", prev.ApprovalPolicyID, cur.ApprovalPolicyID},
	} {
		if !equalStringPtrV4(f.a, f.b) {
			return f.name
		}
	}
	if !equalTimePtrV4(prev.CreatedAt, cur.CreatedAt) {
		return "CreatedAt"
	}
	if !equalTimePtrV4(prev.ExpiresAt, cur.ExpiresAt) {
		return "ExpiresAt"
	}
	if *prev.RequesterManagersSource != *cur.RequesterManagersSource {
		return "RequesterManagersSource"
	}
	return ""
}

// managerSetGrowthV4 reports whether cur grows prev without altering an
// existing entry — every previous manager entry survives identically — while
// adding at least one DECIDING HUMAN: Kind human (1) with Role accountable
// (0) or approver (1). Informed members and agent members never count toward
// the deciding-human requirement, regardless of Primary.
func managerSetGrowthV4(prev, cur []ManagerEntryV4) bool {
	if len(cur) <= len(prev) {
		return false
	}
	type entryKey struct {
		actorID string
		kind    types.ActorKind
		role    types.ManagerRole
		primary bool
	}
	remaining := make(map[entryKey]int, len(cur))
	for _, e := range cur {
		remaining[entryKey{*e.ActorID, *e.Kind, *e.Role, *e.Primary}]++
	}
	for _, e := range prev {
		k := entryKey{*e.ActorID, *e.Kind, *e.Role, *e.Primary}
		if remaining[k] == 0 {
			return false // an existing entry was altered or removed
		}
		remaining[k]--
	}
	addedDecidingHuman := false
	for _, e := range cur {
		k := entryKey{*e.ActorID, *e.Kind, *e.Role, *e.Primary}
		if remaining[k] == 0 {
			continue // consumed by the preserved prefix
		}
		remaining[k]--
		if *e.Kind == types.KindHuman && (*e.Role == types.ManagerAccountable || *e.Role == types.ManagerApprover) {
			addedDecidingHuman = true
		}
	}
	return addedDecidingHuman
}

func equalStringPtrV4(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func equalTimePtrV4(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}
