package verifier

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
	"github.com/aaes-ai/aaesverify/internal/types"
)

// buildGappedLog builds an entry stream with a hole in the sequence numbers,
// optionally ending in a tombstone entry that names the hole. It is an
// independent reimplementation of the producer's claim, like buildLog.
func buildGappedLog(t *testing.T, sequences []uint64, tomb *TombstoneView) ([]EntryView, hash.TreeHead, ed25519.PublicKey) {
	t.Helper()
	base := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	prev := ""
	leaves := make([]string, 0, len(sequences))
	entries := make([]EntryView, 0, len(sequences))
	for i, seq := range sequences {
		e := EntryView{
			TenantID:    "tenant-a",
			Sequence:    seq,
			RecordHash:  fmt.Sprintf("record-%d", seq),
			IntentID:    fmt.Sprintf("intent-%d", seq),
			ActorID:     "agent-1",
			Capability:  "payments.transfer",
			Tier:        types.R3RiskTier,
			Allowed:     true,
			GrantID:     fmt.Sprintf("grant-%d", seq),
			AmountMinor: types.USDM(float64(seq) * 3.25).Minor, AmountCurrency: "USD",
			OccurredAt: base.Add(time.Duration(seq) * time.Second),
			LinkedAt:   base.Add(time.Duration(seq) * time.Second),
		}
		if tomb != nil && i == len(sequences)-1 {
			e.Tombstone = tomb
		}
		pre, err := e.preimage()
		if err != nil {
			t.Fatalf("preimage %d: %v", seq, err)
		}
		chain := hash.Chain(prev, pre)
		leaf := hash.SHA256Hex(pre)
		e.ChainHash = chain
		e.Leaf = leaf
		prev = chain
		entries = append(entries, e)
		leaves = append(leaves, leaf)
	}
	head := hash.TreeHead{
		// The tenant-derived log id, as the producer stamps it; without it the
		// fixture head is legacy material and every export below would fail.
		LogID:    hash.DeriveLogID("tenant-a"),
		Index:    sequences[len(sequences)-1],
		RootHash: hash.MerkleRoot(leaves),
		TreeSize: uint64(len(entries)),
		SignedAt: base.Add(time.Hour),
	}
	head.Signature = ed25519.Sign(testPriv(), HeadPayload(head))
	return entries, head, testPub()
}

func retentionTombstone() *TombstoneView {
	return &TombstoneView{
		FromSequence: 1,
		ToSequence:   6,
		Reason:       "contractual retention: 30 days",
		AuthorizedBy: "operator:alice",
		PolicyID:     "rp_acme_default",
		RecordCount:  6,
		ReceiptCount: 6,
		RemovedAt:    time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC),
	}
}

// The point of the tombstone: a range removed UNDER one verifies, as a distinct
// result that is never a bare PASS, and it names the missing range.
func TestTombstonedGapVerifiesAsOKWithGaps(t *testing.T) {
	entries, head, pub := buildGappedLog(t, []uint64{7, 8, 9, 10, 11}, retentionTombstone())
	doc := exportJSONL(t, entries, head, pub)
	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil {
		t.Fatalf("VerifyExportReader: %v", err)
	}
	if !res.OK {
		t.Fatalf("a tombstoned gap did not verify: %v", res.Errors)
	}
	if !res.Gapped {
		t.Fatal("a tombstoned gap did not report itself as gapped")
	}
	if len(res.Gaps) != 1 {
		t.Fatalf("gaps: %+v", res.Gaps)
	}
	g := res.Gaps[0]
	if g.FromSequence != 1 || g.ToSequence != 6 {
		t.Fatalf("gap names %d..%d, want 1..6", g.FromSequence, g.ToSequence)
	}
	if g.TombstoneSequence != 11 || g.Reason == "" || g.AuthorizedBy != "operator:alice" || g.PolicyID != "rp_acme_default" {
		t.Fatalf("gap does not carry the tombstone that explains it: %+v", g)
	}
	if res.TombstonesChecked != 1 {
		t.Fatalf("tombstones_checked = %d, want 1", res.TombstonesChecked)
	}
	if !res.ChainOK || !res.RootOK || !res.SignatureOK {
		t.Fatalf("a gapped export must still verify its chain and head: %+v", res)
	}
	joined := strings.Join(res.Warnings, " ")
	if !strings.Contains(joined, "1..6") {
		t.Fatalf("warnings do not name the missing range: %v", res.Warnings)
	}
}

// The distinction retention must be distinguishable from: the SAME hole with no
// tombstone is a deleted record, and it fails.
func TestGapWithoutATombstoneFails(t *testing.T) {
	entries, head, pub := buildGappedLog(t, []uint64{7, 8, 9, 10}, nil)
	doc := exportJSONL(t, entries, head, pub)
	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil {
		t.Fatalf("VerifyExportReader: %v", err)
	}
	if res.OK {
		t.Fatal("a hole with no tombstone verified")
	}
	joined := strings.Join(res.Errors, " ")
	if !strings.Contains(joined, "1..6") || !strings.Contains(joined, "no tombstone names it") {
		t.Fatalf("refusal does not name the missing range and the missing tombstone: %v", res.Errors)
	}
}

// A tombstone is only evidence if it says why and who; an anonymous tombstone
// is refused rather than accepted as an explanation.
func TestTombstoneMustStateItsReasonAndAuthor(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*TombstoneView)
		frag string
	}{
		{"no reason", func(tv *TombstoneView) { tv.Reason = "" }, "states no reason"},
		{"no author", func(tv *TombstoneView) { tv.AuthorizedBy = "" }, "no authorising"},
		{"no removal time", func(tv *TombstoneView) { tv.RemovedAt = time.Time{} }, "no removal time"},
		{"inverted range", func(tv *TombstoneView) { tv.FromSequence = 6; tv.ToSequence = 1 }, "is not a range"},
		{"zero from", func(tv *TombstoneView) { tv.FromSequence = 0 }, "is not a range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tomb := retentionTombstone()
			tc.mut(tomb)
			entries, head, pub := buildGappedLog(t, []uint64{7, 8, 9, 10, 11}, tomb)
			doc := exportJSONL(t, entries, head, pub)
			res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{AllowPreAnchor: true})
			if err != nil {
				t.Fatalf("VerifyExportReader: %v", err)
			}
			if res.OK {
				t.Fatalf("an invalid tombstone (%s) verified", tc.name)
			}
			if !strings.Contains(strings.Join(res.Errors, " "), tc.frag) {
				t.Fatalf("refusal for %s does not name %q: %v", tc.name, tc.frag, res.Errors)
			}
		})
	}
}

// A tombstone that names its own sequence or a later one would explain away the
// record that carries it; the log refuses it.
func TestTombstoneMustPrecedeItsOwnSequence(t *testing.T) {
	tomb := retentionTombstone()
	tomb.ToSequence = 11
	entries, head, pub := buildGappedLog(t, []uint64{7, 8, 9, 10, 11}, tomb)
	doc := exportJSONL(t, entries, head, pub)
	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("a tombstone naming its own sequence verified")
	}
	if !strings.Contains(strings.Join(res.Errors, " "), "does not precede") {
		t.Fatalf("refusal does not name the ordering rule: %v", res.Errors)
	}
}

// The tombstone is inside the hash-chained entry, so editing it after the log
// was signed breaks the chain. A tombstone outside the head signature would be
// a way to explain away any deletion.
func TestAnEditedTombstoneBreaksTheChain(t *testing.T) {
	entries, head, pub := buildGappedLog(t, []uint64{7, 8, 9, 10, 11}, retentionTombstone())
	doc := exportJSONL(t, entries, head, pub)
	edited := strings.Replace(doc, "contractual retention: 30 days", "no reason at all", 1)
	if edited == doc {
		t.Fatal("the fixture did not contain the reason, so the edit would prove nothing")
	}
	res, err := VerifyExportReaderWithOptions(strings.NewReader(edited), pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("an edited tombstone verified")
	}
	if !strings.Contains(strings.Join(res.Errors, " "), "chain hash") {
		t.Fatalf("refusal does not name the chain: %v", res.Errors)
	}
}

// A ledger that linked the removed entries before the removal still exports
// them: nothing is missing, so the result is OK and NOT gapped, and the warning
// says why the tombstone is there.
func TestTombstoneOverEntriesStillPresentWarnsButVerifies(t *testing.T) {
	tomb := retentionTombstone()
	tomb.FromSequence = 1
	tomb.ToSequence = 3
	entries, head, pub := buildGappedLog(t, []uint64{1, 2, 3, 4}, tomb)
	doc := exportJSONL(t, entries, head, pub)
	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("a tombstone over present entries failed verification: %v", res.Errors)
	}
	if res.Gapped {
		t.Fatal("nothing is missing, so the result must not be gapped")
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "still contains") {
		t.Fatalf("warnings do not explain the present-range tombstone: %v", res.Warnings)
	}
}
