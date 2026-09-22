package verifier

import "bytes"

// Only caller-pinned witness identities can establish independent evidence.
// The log's own signing key cannot count as another party, even if configured.
func independentWitness(w WitnessView, ledgerKey []byte, trusted map[string][]byte) bool {
	key, ok := trusted[w.WitnessID]
	return ok && len(key) > 0 && bytes.Equal(w.PublicKey, key) && !bytes.Equal(key, ledgerKey)
}
