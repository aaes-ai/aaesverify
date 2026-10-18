package verifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

const TrustReceiptSchema = "aaes.trust-receipt/v1"

const trustReceiptProves = "this decision record was committed to the signed log under the given key"

var trustReceiptDoesNotProve = [...]string{
	"the action executed",
	"the record set is complete",
	"anything the signature does not cover",
}

// TrustReceiptClaims is the fixed claim set every decision receipt carries.
type TrustReceiptClaims struct {
	Proves       string   `json:"proves"`
	DoesNotProve []string `json:"does_not_prove"`
}

// FixedTrustReceiptClaims returns the only claim set valid in schema v1.
func FixedTrustReceiptClaims() TrustReceiptClaims {
	return TrustReceiptClaims{
		Proves:       trustReceiptProves,
		DoesNotProve: append([]string(nil), trustReceiptDoesNotProve[:]...),
	}
}

// TrustReceipt is one decision entry and the signed-log evidence for it.
type TrustReceipt struct {
	Schema string               `json:"schema"`
	Entry  *EntryView           `json:"entry"`
	Leaf   string               `json:"leaf"`
	Proof  *hash.InclusionProof `json:"proof"`
	Head   *hash.TreeHead       `json:"head"`
	Anchor *AnchorView          `json:"anchor,omitempty"`
	Claims TrustReceiptClaims   `json:"claims"`
}

// MarshalIndent encodes one receipt document with a trailing newline.
func (r TrustReceipt) MarshalIndent() ([]byte, error) {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// VerifyTrustReceipt strictly decodes and verifies one decision receipt. Anchor
// witnesses are carried unverified; independence is assessed only by full
// export verification.
func VerifyTrustReceipt(raw []byte, pubKey []byte) (TrustReceipt, error) {
	r, err := decodeTrustReceipt(raw)
	if err != nil {
		return TrustReceipt{}, err
	}
	if err := verifyTrustReceipt(r, pubKey); err != nil {
		return TrustReceipt{}, err
	}
	return r, nil
}

func decodeTrustReceipt(raw []byte) (TrustReceipt, error) {
	if err := checkDuplicateJSONKeys(raw); err != nil {
		return TrustReceipt{}, fmt.Errorf("%w: decode %s: %v", ErrReceipt, TrustReceiptSchema, err)
	}
	var r TrustReceipt
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return TrustReceipt{}, fmt.Errorf("%w: decode %s: %v", ErrReceipt, TrustReceiptSchema, err)
	}
	err := dec.Decode(new(any))
	switch {
	case err == io.EOF:
	case err == nil:
		return TrustReceipt{}, fmt.Errorf("%w: multiple JSON documents", ErrReceipt)
	default:
		return TrustReceipt{}, fmt.Errorf("%w: trailing data: %v", ErrReceipt, err)
	}
	return r, nil
}

func checkDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return checkJSONValue(dec)
}

func checkJSONValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			token, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return fmt.Errorf("object key has type %T", token)
			}
			folded := foldJSONKey(key)
			if _, exists := seen[folded]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[folded] = struct{}{}
			if err := checkJSONValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := checkJSONValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func foldJSONKey(key string) string {
	var folded strings.Builder
	folded.Grow(len(key))
	for _, r := range key {
		if r < utf8.RuneSelf {
			if 'a' <= r && r <= 'z' {
				r -= 'a' - 'A'
			}
		} else {
			r = foldJSONKeyRune(r)
		}
		folded.WriteRune(r)
	}
	return folded.String()
}

func foldJSONKeyRune(r rune) rune {
	for {
		next := unicode.SimpleFold(r)
		if next <= r {
			return next
		}
		r = next
	}
}

func verifyTrustReceipt(r TrustReceipt, pubKey []byte) error {
	if r.Schema != TrustReceiptSchema {
		return fmt.Errorf("%w: schema %q, want %q", ErrReceipt, r.Schema, TrustReceiptSchema)
	}
	if len(pubKey) == 0 {
		return ErrNoPublicKey
	}
	if r.Entry == nil {
		return fmt.Errorf("%w: no decision entry attached", ErrReceipt)
	}
	if r.Entry.Tombstone != nil {
		return fmt.Errorf("%w: tombstone entries are not decision receipts", ErrReceipt)
	}
	if r.Head == nil {
		return fmt.Errorf("%w: no signed tree head attached", ErrReceipt)
	}
	if r.Proof == nil {
		return fmt.Errorf("%w: no inclusion proof attached", ErrReceipt)
	}
	if r.Leaf == "" {
		return fmt.Errorf("%w: no leaf attached", ErrReceipt)
	}
	claims := FixedTrustReceiptClaims()
	if r.Claims.Proves != claims.Proves || !slices.Equal(r.Claims.DoesNotProve, claims.DoesNotProve) {
		return fmt.Errorf("%w: claims do not match the fixed decision-only claim set", ErrReceipt)
	}
	return checkTrustReceiptEvidence(r, pubKey)
}

func checkTrustReceiptEvidence(r TrustReceipt, pubKey []byte) error {
	leaf, err := r.Entry.RecomputeLeaf()
	if err != nil {
		return fmt.Errorf("%w: recompute entry leaf: %v", ErrReceipt, err)
	}
	if leaf != r.Leaf {
		return fmt.Errorf("%w: leaf %s recomputed from the entry is %s", ErrReceipt, r.Leaf, leaf)
	}
	if r.Entry.Leaf != leaf {
		return fmt.Errorf("%w: entry leaf %s, recomputed leaf %s", ErrReceipt, r.Entry.Leaf, leaf)
	}
	if err := VerifyTreeHead(*r.Head, pubKey, r.Head.Algorithm); err != nil {
		return err
	}
	if err := checkHeadLogID(*r.Head, hash.DeriveLogID(r.Entry.TenantID)); err != nil {
		return err
	}
	if err := checkTrustReceiptProof(r); err != nil {
		return err
	}
	return checkTrustReceiptAnchor(r, pubKey)
}

func checkTrustReceiptAnchor(r TrustReceipt, pubKey []byte) error {
	if r.Anchor == nil {
		return nil
	}
	if err := VerifyTreeHead(r.Anchor.Head, pubKey, r.Anchor.Head.Algorithm); err != nil {
		return fmt.Errorf("anchor head: %w", err)
	}
	if r.Anchor.Head.TreeSize < r.Proof.TreeSize {
		return fmt.Errorf("%w: anchor head covers %d leaves, proof covers %d", ErrReceipt, r.Anchor.Head.TreeSize, r.Proof.TreeSize)
	}
	return nil
}

func checkTrustReceiptProof(r TrustReceipt) error {
	if r.Proof.TreeSize > r.Head.TreeSize {
		return fmt.Errorf("%w: proof covers %d leaves, head covers %d", ErrReceipt, r.Proof.TreeSize, r.Head.TreeSize)
	}
	if r.Proof.RootHash != r.Head.RootHash {
		return fmt.Errorf("%w: proof root %s, head root %s", ErrReceipt, r.Proof.RootHash, r.Head.RootHash)
	}
	if !hash.VerifyInclusion(r.Leaf, *r.Proof) {
		return ErrInclusion
	}
	return nil
}
