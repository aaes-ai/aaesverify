package verifier

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
	"github.com/aaes-ai/aaesverify/internal/types"
)

func TestEntryViewAmount(t *testing.T) {
	v2 := EntryView{AmountMinor: 1950, AmountCurrency: "USD"}
	if got := v2.Amount(); got != (types.Money{Minor: 1950, Currency: "USD"}) {
		t.Fatalf("v2 Amount() = %+v", got)
	}
	zero := EntryView{}
	if got := zero.Amount(); !got.IsZero() || got.Currency != "" {
		t.Fatalf("zero Amount() = %+v", got)
	}
}

func TestV2ExportIncludingZeroAmountVerifies(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	tenant := "acme"
	entries := []EntryView{
		{
			TenantID: tenant, Sequence: 1, RecordHash: hash.SHA256Hex([]byte("r1")),
			IntentID: "i1", ActorID: "a1", Capability: "read", Tier: types.R0RiskTier,
			Allowed: true, OccurredAt: now, LinkedAt: now,
		},
		{
			TenantID: tenant, Sequence: 2, RecordHash: hash.SHA256Hex([]byte("r2")),
			IntentID: "i2", ActorID: "a2", Capability: "spend", Tier: types.R3RiskTier,
			Allowed: true, AmountMinor: 2500, AmountCurrency: "USD",
			OccurredAt: now, LinkedAt: now,
		},
	}
	doc := sealSchemaExport(t, ExportSchemaV2, tenant, entries, pub, priv, now)
	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("v2 export failed: %v", res.Errors)
	}
	loaded, err := LoadExportReader(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Entries[0].Amount(); !got.IsZero() || got.Currency != "" {
		t.Fatalf("zero-amount entry Amount() = %+v", got)
	}
	if got := loaded.Entries[1].Amount(); got != (types.Money{Minor: 2500, Currency: "USD"}) {
		t.Fatalf("nonzero Amount() = %+v", got)
	}
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func sealSchemaExport(t *testing.T, schema, tenant string, entries []EntryView, pub ed25519.PublicKey, priv ed25519.PrivateKey, now time.Time) string {
	t.Helper()
	prev := ""
	leaves := make([]string, len(entries))
	var entryLines []string
	for i, e := range entries {
		pre, err := e.preimage()
		if err != nil {
			t.Fatal(err)
		}
		leaf := hash.SHA256Hex(pre)
		chain := hash.Chain(prev, pre)
		obj := map[string]any{
			"type": "entry", "tenant_id": e.TenantID, "sequence": e.Sequence,
			"record_hash": e.RecordHash, "intent_id": e.IntentID, "actor_id": e.ActorID,
			"capability": e.Capability, "tier": e.Tier, "allowed": e.Allowed,
			"grant_id": e.GrantID, "occurred_at": e.OccurredAt, "linked_at": e.LinkedAt,
			"leaf": leaf, "chain_hash": chain,
		}
		if e.AmountMinor != 0 || e.AmountCurrency != "" {
			obj["amount_minor"] = e.AmountMinor
			obj["amount_currency"] = e.AmountCurrency
		}
		line, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		entryLines = append(entryLines, string(line))
		leaves[i] = leaf
		prev = chain
	}
	root := hash.MerkleRoot(leaves)
	head := hash.TreeHead{
		LogID:    hash.DeriveLogID(tenant),
		Index:    entries[len(entries)-1].Sequence,
		RootHash: root, TreeSize: uint64(len(entries)), SignedAt: now,
	}
	head.Signature = ed25519.Sign(priv, HeadPayload(head))
	hdr, err := json.Marshal(map[string]any{
		"type": "header", "schema": schema, "log_id": "test-log", "tenant_id": tenant,
		"exported_at": now, "entry_count": len(entries), "head": head,
		"public_key": hex.EncodeToString(pub), "pre_anchor": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.Write(hdr)
	b.WriteByte('\n')
	for _, line := range entryLines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func TestCurrentSchemaRefusesLegacyAmount(t *testing.T) {
	raw := `{"type":"entry","amount_usd":0,"amount_minor":100,"amount_currency":"USD"}`
	if _, err := decodeEntryLine([]byte(raw), ExportSchemaV2, 2); err == nil || !strings.Contains(err.Error(), "legacy amount_usd") {
		t.Fatalf("mixed amount layout accepted: %v", err)
	}
}
