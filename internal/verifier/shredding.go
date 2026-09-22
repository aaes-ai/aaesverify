package verifier

// This file is the verifier's reading of the journal crypto-shredding seam
// (docs/engineering/JOURNAL-SHREDDING.md). It changes no check: the chain, the
// leaves, the root and the signatures are computed over the stored bytes, and
// a protected field IS stored bytes — ciphertext with an enc:v1: marker. What
// this file adds is the honest report on top: how many entries carry protected
// identifiers, and whether a sealed record states that the tenant's journal
// key was destroyed, which makes those fields unreadable-after-shredding.

import (
	"strconv"
	"strings"
	"time"
)

// ProtectedFieldMarker is the enc:v1: prefix a journal-protected field value
// carries. It is duplicated from internal/journalcrypt.MarkerPrefix on
// purpose: this package must not import the producer (the same discipline as
// ExportSchema), and a cross-package test fails the build if the two drift.
const ProtectedFieldMarker = "enc:v1:"

// KeyShredCapability names the governance record a journal-key destruction is
// sealed as. Duplicated from internal/journalcrypt.ShredCapability under the
// same rule and the same test.
const KeyShredCapability = "journal.key-shred"

// ShredEventView names one sealed record stating that a tenant's journal
// encryption key was destroyed. The record is a claim the chain commits to —
// it is evidence that the destruction was recorded, and the verifier reports
// it as such; whether the key file is actually gone is a fact about the key
// directory, not the export.
type ShredEventView struct {
	TenantID   string    `json:"tenant_id"`
	Sequence   uint64    `json:"sequence"`
	OccurredAt time.Time `json:"occurred_at"`
}

// checkShredding reports the export's protected fields and key-destruction
// records. It runs only after the chain verified (the same ordering as the gap
// check): a report about what entries MEAN is worth nothing until what entries
// ARE is established. Nothing here can fail an export: shredding is a reading
// of intact evidence, never a chain failure.
func checkShredding(exp *ExportFile, res *Result) {
	for _, e := range exp.Entries {
		if strings.HasPrefix(e.ActorID, ProtectedFieldMarker) {
			res.ProtectedEntries++
		}
		if e.Capability == KeyShredCapability {
			res.ShredEvents = append(res.ShredEvents, ShredEventView{
				TenantID:   e.TenantID,
				Sequence:   e.Sequence,
				OccurredAt: e.OccurredAt,
			})
		}
	}
	if res.ProtectedEntries > 0 {
		res.Warnings = append(res.Warnings,
			"this export carries journal-encrypted identifier fields (enc:v1:); the chain verifies over the ciphertext exactly as stored, and reading the plaintext requires the tenant's journal key, which the export does not contain")
	}
	for _, ev := range res.ShredEvents {
		res.Warnings = append(res.Warnings,
			"a sealed record at sequence "+strconv.FormatUint(ev.Sequence, 10)+" states that tenant "+ev.TenantID+
				" destroyed its journal encryption key at "+ev.OccurredAt.UTC().Format(time.RFC3339)+
				"; that tenant's journal-encrypted identifier fields are unreadable after shredding — this is a recorded erasure, not a chain failure")
	}
}
