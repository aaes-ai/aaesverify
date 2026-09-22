package verifier

import "encoding/hex"

// witnessIdentities counts independent parties: one public key cannot
// establish two identities, and one identity cannot be counted twice by
// rotating keys or copying an unsigned WitnessID.
type witnessIdentities struct {
	byKey map[string]string
	byID  map[string]string
}

func (w *witnessIdentities) add(id string, pub []byte) bool {
	if w.byKey == nil {
		w.byKey = map[string]string{}
		w.byID = map[string]string{}
	}
	key := hex.EncodeToString(pub)
	if _, ok := w.byKey[key]; ok {
		return false
	}
	if _, ok := w.byID[id]; ok {
		return false
	}
	w.byKey[key] = id
	w.byID[id] = key
	return true
}
