package hash

import (
	"strings"
	"testing"
)

// The derivation is the contract between the producer and the offline
// verifier, so its properties are pinned directly: the same tenant must always
// derive the same id (a restart, a different machine or a rebuilt export cannot
// change it), two tenants must never share one id (a witnessed head from one
// log must never validate as another log's), and the id must be visibly
// domain-separated rather than a bare hash an operator-chosen name could be
// crafted to imitate.
func TestDeriveLogIDIsStableAndTenantDistinct(t *testing.T) {
	a, again := DeriveLogID("tenant-a"), DeriveLogID("tenant-a")
	if a == "" || a != again {
		t.Fatalf("DeriveLogID is not deterministic: %q vs %q", a, again)
	}
	if a == DeriveLogID("tenant-b") {
		t.Fatal("two tenants derived the same log id")
	}
	if !strings.HasPrefix(a, "aaes/log-id/1/") {
		t.Fatalf("derived id %q is not domain-separated by the scheme prefix", a)
	}
}

// An empty tenant id still derives a well-formed id: the ledger refuses
// tenantless entries long before a head is built, but a helper that returned
// "" for some input would hand the verifier no way to tell a derived id from
// legacy material.
func TestDeriveLogIDNeverReturnsEmpty(t *testing.T) {
	if got := DeriveLogID(""); got == "" {
		t.Fatal("DeriveLogID(\"\") is empty")
	}
}
