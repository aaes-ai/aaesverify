package hash

import (
	"crypto/sha256"
	"encoding/hex"
)

// logIDDomain separates the derivation from every other SHA-256 use in this
// package (leaves, nodes, chain links), so a derived id can never collide with
// one of them, and a future change to the scheme is an explicit constant bump
// rather than a silent re-derivation that splits old and new heads.
const logIDDomain = "aaes/log-id/1/"

// DeriveLogID returns the log identity a tenant's tree heads carry in
// TreeHead.LogID. It is deterministic in the tenant id alone — not in the
// operator's display name for the log, not in the deployment — because the
// offline verifier must be able to recompute it from nothing but the export
// header's tenant_id, and a derivation that also depended on local
// configuration would make every export unverifiable anywhere else.
//
// This is the ONE helper shared by the producer (internal/audit, which stamps
// it where heads are built) and the verifier (internal/verifier, which
// requires heads to carry it). Both import this package — the verifier is
// constrained to stdlib, internal/hash and internal/types — so the two sides
// cannot drift onto different derivations without failing to compile against
// the same function.
func DeriveLogID(tenantID string) string {
	sum := sha256.Sum256([]byte(logIDDomain + tenantID))
	return logIDDomain + hex.EncodeToString(sum[:])
}
