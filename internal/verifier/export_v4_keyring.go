package verifier

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// Keyring resolution (design section 4.7) is per head, not per file: the
// final head resolves through the header's required signing_key_id and every
// anchor through its required key_id. An unknown or missing key id is an
// export error, never a head to skip silently. The embedded header public_key
// is an internal-consistency fallback only: it cannot resolve other heads and
// cannot satisfy any current-v4 freshness mode.

// resolveFinalKeyV4 resolves the final head's signing key. With a keyring,
// signing_key_id must name an entry and an embedded key that disagrees with
// that entry is one key id naming two different keys — a configuration error.
// Without a keyring the embedded key is the fallback, and any requested
// freshness mode fails closed.
func resolveFinalKeyV4(exp *ExportFile, opts VerifyOptions, res *Result) (ed25519.PublicKey, error) {
	keyID := exp.Header.SigningKeyID
	if opts.Keyring != nil {
		key, ok := opts.Keyring[keyID]
		if !ok {
			return nil, fmt.Errorf("%w: signing_key_id %q", ErrUnknownKeyID, keyID)
		}
		res.KeySource = "keyring"
		if exp.Header.PublicKey != "" {
			if embedded, err := ParsePublicKey(exp.Header.PublicKey); err == nil && !bytes.Equal(embedded, key) {
				return nil, fmt.Errorf("%w: embedded public key disagrees with keyring entry %q; one key id names two different keys", ErrTrustConfig, keyID)
			}
		}
		return key, nil
	}
	if freshnessModesSetV4(opts) > 0 {
		return nil, fmt.Errorf("%w: v4 freshness modes require a caller-pinned keyring; an embedded key proves internal consistency only", ErrNoPublicKey)
	}
	if exp.Header.PublicKey != "" {
		key, err := ParsePublicKey(exp.Header.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: embedded public key: %v", ErrMalformed, err)
		}
		res.KeySource = "embedded"
		return key, nil
	}
	return nil, ErrNoPublicKey
}

// callerKeyOptionsV4 makes a caller-supplied public key (aaesverify and
// aaesctl verify --pubkey) the trust anchor of a v4 export. Without a keyring
// the key becomes a one-entry keyring under the header's signing_key_id, so
// anchors under any other key id fail as unknown. With a keyring the key must
// be that keyring's signing_key_id entry. An embedded key that differs is
// refused, as on the v2/v3 path: ignoring the caller's key would let a file
// signed by any embedded key pass a caller who pinned the genuine one.
func callerKeyOptionsV4(exp *ExportFile, pubKey []byte, opts VerifyOptions) (VerifyOptions, error) {
	if len(pubKey) == 0 {
		return opts, nil
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return opts, fmt.Errorf("%w: the supplied public key is %d bytes, want %d", ErrMalformed, len(pubKey), ed25519.PublicKeySize)
	}
	if exp.Header.PublicKey != "" {
		if embedded, err := ParsePublicKey(exp.Header.PublicKey); err == nil && !bytes.Equal(embedded, pubKey) {
			return opts, fmt.Errorf("%w: export was signed by %s, verifier was given %s",
				ErrKeyMismatch, hex.EncodeToString(embedded), hex.EncodeToString(pubKey))
		}
	}
	keyID := exp.Header.SigningKeyID
	if opts.Keyring != nil {
		if key, ok := opts.Keyring[keyID]; !ok || !bytes.Equal(key, pubKey) {
			return opts, fmt.Errorf("%w: the supplied public key is not keyring entry %q", ErrTrustConfig, keyID)
		}
		return opts, nil
	}
	opts.Keyring = map[string]ed25519.PublicKey{keyID: ed25519.PublicKey(append([]byte(nil), pubKey...))}
	return opts, nil
}

// resolveAnchorKeyV4 resolves one anchor's required key_id. A v4 anchor
// without a key_id is an error: a legacy keyless anchor is incompatible with
// a v4 export even though retained v2/v3 files keep their historical
// single-key behaviour in legacy mode.
func resolveAnchorKeyV4(i int, keyID string, opts VerifyOptions) (ed25519.PublicKey, error) {
	if keyID == "" {
		return nil, fmt.Errorf("anchor %d: a v4 anchor requires a key_id naming the key that signed its head", i)
	}
	if opts.Keyring == nil {
		return nil, fmt.Errorf("anchor %d: %w: %q (no caller-pinned keyring)", i, ErrUnknownKeyID, keyID)
	}
	key, ok := opts.Keyring[keyID]
	if !ok {
		return nil, fmt.Errorf("anchor %d: %w: %q", i, ErrUnknownKeyID, keyID)
	}
	return key, nil
}

// keyringValuesV4 is the whole authorised logical-log keyring BY VALUE: every
// active, retired or otherwise authorised ledger key epoch. A witness whose
// public-key bytes match any of them is ledger self-attestation, never an
// independent party — rotation does not turn the ledger into one. Without a
// keyring the resolved final key is the only known ledger key.
func keyringValuesV4(opts VerifyOptions, finalKey ed25519.PublicKey, resolved bool) [][]byte {
	if opts.Keyring != nil {
		values := make([][]byte, 0, len(opts.Keyring))
		for _, k := range opts.Keyring {
			values = append(values, k)
		}
		return values
	}
	if resolved && len(finalKey) > 0 {
		return [][]byte{finalKey}
	}
	return nil
}

// checkTrustContextV4 enforces the section 4.7 trust-context invariant: when
// independent evidence is requested, or the result is PASS-eligible
// (expected-final mode), the authorised ledger keyring values and the
// trusted-independent-witness pin values must be disjoint by public-key
// bytes. Overlap is a configuration error. In a non-independent mode an
// overlapping signature may still verify, but it is always reported as
// non-independent by independentWitnessV4.
func checkTrustContextV4(opts VerifyOptions) error {
	if !opts.RequireIndependent && opts.ExpectedFinal == nil {
		return nil
	}
	for keyID, ledgerKey := range opts.Keyring {
		for witnessID, witnessKey := range opts.TrustedWitnessKeys {
			if bytes.Equal(ledgerKey, witnessKey) {
				return fmt.Errorf("%w: ledger key %q and trusted witness %q are the same key; keys must be disjoint by public-key bytes", ErrTrustConfig, keyID, witnessID)
			}
		}
	}
	return nil
}

// independentWitnessV4 applies the whole-keyring exclusion of section 4.7:
// the witness identity must be caller-pinned, the pinned key must match the
// exported key bytes, and those bytes must not name ANY authorised ledger key
// epoch. Comparisons are by public-key bytes, never key ids, so assigning one
// key multiple ledger and witness ids cannot bypass the exclusion.
func independentWitnessV4(w WitnessView, excluded [][]byte, trusted map[string][]byte) bool {
	key, ok := trusted[w.WitnessID]
	if !ok || len(key) == 0 || !bytes.Equal(w.PublicKey, key) {
		return false
	}
	for _, ledgerKey := range excluded {
		if bytes.Equal(key, ledgerKey) {
			return false
		}
	}
	return true
}

func encodeKeyHexV4(key ed25519.PublicKey) string {
	return hex.EncodeToString(key)
}
