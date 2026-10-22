package verifytext

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aaes-ai/aaesverify/internal/verifier"
)

// The v4 trust files shared by aaesctl verify and aaesverify. Both come from
// the examiner, never from the export being examined.

// LoadKeyring reads a --keyring file: a JSON object mapping each authorised
// ledger key_id of one logical log to its hex or base64 Ed25519 public key.
// An empty path means no keyring was supplied.
func LoadKeyring(path string) (map[string]ed25519.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keyring: %w", err)
	}
	var encoded map[string]string
	if err := decodeTrustFile(raw, &encoded); err != nil {
		return nil, fmt.Errorf("keyring must be a JSON object mapping key ids to public keys: %w", err)
	}
	if len(encoded) == 0 {
		return nil, fmt.Errorf("keyring names no keys")
	}
	keys := make(map[string]ed25519.PublicKey, len(encoded))
	for id, text := range encoded {
		if strings.TrimSpace(id) == "" || strings.TrimSpace(id) != id {
			return nil, fmt.Errorf("keyring contains an empty or padded key id")
		}
		key, err := verifier.ParsePublicKey(text)
		if err != nil {
			return nil, fmt.Errorf("keyring key %q: %w", id, err)
		}
		keys[id] = key
	}
	return keys, nil
}

// LoadHeadPin reads an --expected-final file: the exact final head the
// examiner expects, as {"log_id", "index", "root_hash", "tree_size"}. Every
// member is required. An empty path means no pin was supplied.
func LoadHeadPin(path string) (*verifier.HeadPin, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read expected final head: %w", err)
	}
	if err := verifier.CheckJSONMembers(raw, verifier.HeadPin{}); err != nil {
		return nil, fmt.Errorf("expected final head: %w", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, fmt.Errorf("expected final head must be a JSON object: %w", err)
	}
	for _, name := range []string{"log_id", "index", "root_hash", "tree_size"} {
		if _, ok := members[name]; !ok {
			return nil, fmt.Errorf("expected final head lacks %q", name)
		}
	}
	var pin verifier.HeadPin
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pin); err != nil {
		return nil, fmt.Errorf("expected final head: %w", err)
	}
	if pin.LogID == "" || pin.RootHash == "" || pin.TreeSize == 0 {
		return nil, fmt.Errorf("expected final head needs a log_id, a root_hash and a nonzero tree_size")
	}
	return &pin, nil
}

// decodeTrustFile decodes a trust file and refuses a repeated member, so the
// examiner's own file cannot name two values for one key.
func decodeTrustFile(raw []byte, v any) error {
	if err := verifier.CheckJSONMembers(raw, v); err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}
