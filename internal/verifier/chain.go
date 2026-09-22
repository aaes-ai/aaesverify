package verifier

import (
	"crypto/ed25519"
	"fmt"

	"github.com/aaes-dev/aaesverify/internal/hash"
)

// HeadPayload returns the bytes a tree head signature covers: the canonical
// JSON of the head with the signature omitted. Mirrors audit.HeadPayload.
func HeadPayload(h hash.TreeHead) []byte {
	h.Signature = nil
	b, err := hash.CanonicalJSON(h)
	if err != nil {
		return nil
	}
	return b
}

// VerifyTreeHead checks an Ed25519 signature over a tree head.
func VerifyTreeHead(h hash.TreeHead, pubKey []byte) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: public key is %d bytes, want %d", ErrSignature, len(pubKey), ed25519.PublicKeySize)
	}
	if len(h.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is %d bytes, want %d", ErrSignature, len(h.Signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKey), HeadPayload(h), h.Signature) {
		return ErrSignature
	}
	return nil
}

// chainState is the outcome of walking a full export.
type chainState struct {
	leaves      []string
	chainErr    error
	rootErr     error
	sigErr      error
	recomputed  string
	firstSeq    uint64
	lastSeq     uint64
	contiguous  bool
	entryErrors []string
}

// checkChain recomputes everything derivable from the entries and the head,
// reporting each class of failure separately so a Result can show an auditor
// exactly which check failed rather than one opaque "invalid".
func checkChain(entries []EntryView, head hash.TreeHead, pubKey []byte) chainState {
	st := chainState{contiguous: true}
	if len(entries) == 0 {
		st.chainErr = ErrEmptyLog
		return st
	}
	st.firstSeq = entries[0].Sequence
	st.lastSeq = entries[len(entries)-1].Sequence
	leaves := make([]string, len(entries))
	prev := ""
	var prevSeq uint64
	var errs []string
	for i, e := range entries {
		if e.TenantID == "" {
			errs = append(errs, fmt.Sprintf("entry %d: missing tenant_id", i))
		}
		if i > 0 {
			if e.Sequence <= prevSeq {
				errs = append(errs, fmt.Sprintf("entry %d: sequence %d does not follow %d", i, e.Sequence, prevSeq))
			}
			if e.Sequence != prevSeq+1 {
				st.contiguous = false
			}
		}
		chain, leaf, ok := checkEntry(i, e, prev, &errs)
		if !ok {
			continue
		}
		leaves[i] = leaf
		prev = chain
		prevSeq = e.Sequence
	}
	if len(errs) > 0 {
		st.chainErr = fmt.Errorf("%w: %s", ErrChain, errs[0])
		st.entryErrors = errs[1:]
	}
	st.leaves = leaves
	st.recomputed = hash.MerkleRoot(leaves)
	if head.TreeSize != uint64(len(entries)) {
		st.rootErr = fmt.Errorf("%w: head tree_size is %d, export has %d entries", ErrRoot, head.TreeSize, len(entries))
	} else if head.RootHash != st.recomputed {
		st.rootErr = fmt.Errorf("%w: head root is %s, recomputed %s", ErrRoot, head.RootHash, st.recomputed)
	} else if head.Index != entries[len(entries)-1].Sequence {
		st.rootErr = fmt.Errorf("%w: head index is %d, last entry sequence is %d", ErrRoot, head.Index, entries[len(entries)-1].Sequence)
	}
	if len(pubKey) > 0 {
		st.sigErr = VerifyTreeHead(head, pubKey)
	}
	return st
}

// checkEntry recomputes one entry's chain hash and leaf and reports every
// disagreement with the exporter's claims. ok is false when the entry's
// canonical bytes could not be rebuilt at all, in which case it links to
// nothing and the walk leaves the previous chain hash in place.
func checkEntry(i int, e EntryView, prev string, errs *[]string) (chain, leaf string, ok bool) {
	pre, err := e.preimage()
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("entry %d: %v", i, err))
		return "", "", false
	}
	chain = hash.Chain(prev, pre)
	leaf = hash.SHA256Hex(pre)
	if e.ChainHash == "" {
		*errs = append(*errs, fmt.Sprintf("entry %d (sequence %d): missing chain_hash", i, e.Sequence))
	} else if e.ChainHash != chain {
		*errs = append(*errs, fmt.Sprintf("entry %d (sequence %d): chain hash is %s, recomputed %s", i, e.Sequence, e.ChainHash, chain))
	}
	if e.Leaf == "" {
		*errs = append(*errs, fmt.Sprintf("entry %d (sequence %d): missing leaf", i, e.Sequence))
	} else if e.Leaf != leaf {
		*errs = append(*errs, fmt.Sprintf("entry %d (sequence %d): leaf is %s, recomputed %s", i, e.Sequence, e.Leaf, leaf))
	}
	return chain, leaf, true
}

// VerifyChain verifies a complete export: every entry links to the previous
// one from genesis, the leaves hash to the signed head, and the head signature
// verifies under pubKey.
//
// The entries must be the complete log for the tenant, in sequence order. A
// partial window cannot match the head root, which is the intended failure
// mode: a log that can show you an arbitrary slice is not a log.
func VerifyChain(entries []EntryView, head hash.TreeHead, pubKey []byte) error {
	if len(pubKey) == 0 {
		return ErrNoPublicKey
	}
	st := checkChain(entries, head, pubKey)
	if st.chainErr != nil {
		return st.chainErr
	}
	if st.rootErr != nil {
		return st.rootErr
	}
	if st.sigErr != nil {
		return st.sigErr
	}
	return nil
}
