package verifier

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

// verifyEvidence collects the cross-anchor tallies the honesty warnings need:
// whether any non-noop timestamp was seen, and how many witness
// countersignatures covered an earlier prefix of the log rather than the
// final published head.
type verifyEvidence struct {
	sawNonNoopTimestamp    bool
	earlierPrefixWitnesses int
}

// checkExportAnchor verifies one anchor of an export: its signature, the log
// it names, the tree prefix it commits to, and the evidence riding on it. A
// failed anchor is recorded and the walk moves on, so one Result can name
// every bad anchor rather than only the first.
func checkExportAnchor(exp *ExportFile, res *Result, opts VerifyOptions, key []byte, leaves []string, wantLogID string, i int, a AnchorView, independentSeen *witnessIdentities, ev *verifyEvidence) {
	if err := VerifyTreeHead(a.Head, key); err != nil {
		res.AnchorsOK = false
		res.addError("anchor %d: %v", i, err)
		return
	}
	// A valid anchor signature is not enough: one signing key can serve
	// several logs, so the anchor's head must also name THIS log. Without
	// the check a signed head — and the witness countersignatures riding
	// on it — from another log could be spliced in as an anchor here.
	if err := checkHeadLogID(a.Head, wantLogID); err != nil {
		res.AnchorsOK = false
		res.addError("anchor %d: %v", i, err)
		return
	}
	if a.Head.TreeSize == 0 {
		// An anchor over the empty tree commits to no entries, and its root
		// is a constant every log shares — so witnesses on it never
		// attested to this history, and their signatures replay across
		// logs. Reject the anchor outright; accepting it while skipping
		// only the count would still let a size-0 cosignature masquerade as
		// a verified witness of this export.
		res.AnchorsOK = false
		res.addError("anchor %d: tree_size 0 commits to no entries and is never evidence; its witnesses are not counted", i)
		return
	}
	if a.Head.TreeSize > uint64(len(leaves)) {
		res.AnchorsOK = false
		res.addError("anchor %d: covers %d entries, log has %d", i, a.Head.TreeSize, len(leaves))
		return
	}
	if prefixRoot := hash.MerkleRoot(leaves[:a.Head.TreeSize]); prefixRoot != a.Head.RootHash {
		res.AnchorsOK = false
		res.addError("anchor %d: root %s is not the root of the first %d entries (%s)",
			i, a.Head.RootHash, a.Head.TreeSize, prefixRoot)
		return
	}
	res.AnchorsVerified++
	// Independence is a claim about the FINAL published head: a witness
	// that countersigned an earlier prefix vouched for that prefix only,
	// and the entries appended since are unwitnessed. Such cosignatures
	// stay visible in WitnessesVerified but cannot satisfy
	// RequireIndependent.
	coversFinal := headCoversFinal(a.Head, exp.Header.Head)
	if !checkAnchorTimestamp(i, a, res, opts, ev) {
		return
	}
	checkAnchorWitnesses(i, a, res, key, opts, coversFinal, independentSeen, ev)
}

// checkAnchorTimestamp checks the external timestamp one anchor carries and
// reports whether the anchor survived. A digest that does not cover this
// head fails the whole anchor, so its witnesses are not counted either.
func checkAnchorTimestamp(i int, a AnchorView, res *Result, opts VerifyOptions, ev *verifyEvidence) bool {
	if a.Timestamp == nil {
		return true
	}
	res.TimestampsChecked++
	want := sha256.Sum256(HeadPayload(a.Head))
	if a.Timestamp.Digest != hex.EncodeToString(want[:]) {
		res.AnchorsOK = false
		res.addError("anchor %d: timestamp digest %s does not cover this head", i, a.Timestamp.Digest)
		return false
	}
	if !a.Timestamp.Noop {
		ev.sawNonNoopTimestamp = true
		if opts.TSARoots == nil {
			if len(a.Timestamp.Token) == 0 {
				res.Warnings = append(res.Warnings, fmt.Sprintf("anchor %d: timestamp is not a noop but carries no RFC 3161 token, so it was not counted as independent", i))
			}
		} else if err := verifyTimestampWithTrust(*a.Timestamp, opts.TSARoots, time.Time{}); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("anchor %d: timestamp is not independent: %v", i, err))
		} else {
			res.TimestampsIndependent++
		}
	}
	return true
}

// checkAnchorWitnesses verifies each witness countersignature on one anchor
// and counts the independent ones. A countersignature over an earlier prefix
// verifies but is tallied in ev.earlierPrefixWitnesses rather than counted as
// independent evidence for the final head.
func checkAnchorWitnesses(i int, a AnchorView, res *Result, key []byte, opts VerifyOptions, coversFinal bool, independentSeen *witnessIdentities, ev *verifyEvidence) {
	for j, w := range a.Witnesses {
		if len(w.Signature) == 0 {
			continue
		}
		if len(w.PublicKey) != ed25519.PublicKeySize {
			res.AnchorsOK = false
			res.addError("anchor %d witness %d (%s): no verifiable public key in the export", i, j, w.WitnessID)
			continue
		}
		if !ed25519.Verify(ed25519.PublicKey(w.PublicKey), HeadPayload(a.Head), w.Signature) {
			res.AnchorsOK = false
			res.addError("anchor %d witness %d (%s): countersignature does not verify", i, j, w.WitnessID)
			continue
		}
		res.WitnessesVerified++
		if !coversFinal {
			ev.earlierPrefixWitnesses++
			continue
		}
		if independentWitness(w, key, opts.TrustedWitnessKeys) && independentSeen.add(w.WitnessID, w.PublicKey) {
			res.IndependentWitnesses++
		}
	}
}

// checkHeadLogID binds a signed head to the log this export claims to be. The
// wanted id is derived from the header's tenant id — the same derivation the
// producer stamps when it builds heads — so a head from any other log, or a
// head from before log ids existed, is refused by name rather than accepted
// as evidence for this one.
func checkHeadLogID(head hash.TreeHead, wantLogID string) error {
	if head.LogID == "" {
		return fmt.Errorf("%w: a head with no log id cannot be verified as belonging to this log", ErrLegacyHead)
	}
	if head.LogID != wantLogID {
		return fmt.Errorf("%w: head names %q, this export's tenant derives %q", ErrLogIDMismatch, head.LogID, wantLogID)
	}
	return nil
}

// headCoversFinal reports whether a countersigned head commits to the same
// tree state as the export's published head: same log, index, size and root.
// SignedAt is deliberately excluded because anchors are re-signed when they
// are emitted, so an anchor head and the published head legitimately carry
// different signing times over the same tree. Independence is a claim about
// which tree state the witness vouched for, not when the ledger re-signed it.
func headCoversFinal(head, final hash.TreeHead) bool {
	return head.LogID == final.LogID &&
		head.Index == final.Index &&
		head.TreeSize == final.TreeSize &&
		head.RootHash == final.RootHash
}
