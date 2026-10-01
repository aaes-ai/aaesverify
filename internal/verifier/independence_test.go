package verifier

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

var testTSGenTime = time.Date(2026, 9, 12, 15, 4, 5, 0, time.UTC)

func exportJSONLWithAnchors(t *testing.T, entries []EntryView, head hash.TreeHead, pub ed25519.PublicKey, anchors []AnchorView) string {
	t.Helper()
	doc := exportJSONL(t, entries, head, pub)
	// Anchors are present, so pre_anchor would be a lie: that flag is only
	// honest on a snapshot taken before the first interval.
	var hdr map[string]any
	lines := strings.Split(strings.TrimRight(doc, "\n"), "\n")
	if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil {
		t.Fatal(err)
	}
	delete(hdr, "pre_anchor")
	hb, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	lines[0] = string(hb)
	var b strings.Builder
	b.WriteString(strings.Join(lines, "\n"))
	b.WriteByte('\n')
	for _, a := range anchors {
		line := map[string]any{"type": "anchor", "head": a.Head}
		if a.Timestamp != nil {
			line["timestamp"] = a.Timestamp
		}
		if len(a.Witnesses) > 0 {
			line["witnesses"] = a.Witnesses
		}
		raw, err := json.Marshal(line)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	return b.String()
}

func TestNonNoopTimestampWithoutATokenIsNotIndependent(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 4)
	digest := sha256.Sum256(HeadPayload(head))
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{
		Head: head,
		Timestamp: &TimestampView{
			Authority: "pretend-tsa",
			Digest:    hex.EncodeToString(digest[:]),
			Time:      head.SignedAt,
			Noop:      false,
		},
	}})
	res, err := VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("internal consistency failed: %v", res.Errors)
	}
	if res.TimestampsChecked != 1 {
		t.Fatalf("TimestampsChecked = %d, want 1", res.TimestampsChecked)
	}
	if res.TimestampsIndependent != 0 {
		t.Fatalf("TimestampsIndependent = %d, want 0 for a tokenless !Noop timestamp", res.TimestampsIndependent)
	}
	joined := strings.Join(res.Warnings, " ")
	if !strings.Contains(joined, "no RFC 3161 token") && !strings.Contains(joined, "no TSA trust roots") {
		t.Fatalf("warnings do not say the timestamp was not counted as independent: %v", res.Warnings)
	}
}

func TestIndependentWitnessesAreDistinctAcrossAnchors(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 6)
	wpub, wpriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(wpriv, HeadPayload(head))
	w := WitnessView{
		WitnessID: "ext-1",
		PublicKey: wpub,
		Signature: sig,
		SignedAt:  head.SignedAt,
		KeyHolder: "external",
	}
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{
		{Head: head, Witnesses: []WitnessView{w}},
		{Head: head, Witnesses: []WitnessView{w, w}},
	})
	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{TrustedWitnessKeys: map[string][]byte{"ext-1": wpub, "ext-2": wpub}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("export did not verify: %v", res.Errors)
	}
	if res.WitnessesVerified != 3 {
		t.Fatalf("WitnessesVerified = %d, want 3 signatures", res.WitnessesVerified)
	}
	if res.IndependentWitnesses != 1 {
		t.Fatalf("IndependentWitnesses = %d, want 1 distinct (WitnessID, PublicKey)", res.IndependentWitnesses)
	}
}

// A witness that countersigned an EARLIER prefix vouched for that prefix
// only: every entry appended since is unwitnessed, so presenting such an
// export as independently witnessed overstates what the witness saw. The
// cosignature must stay visible (WitnessesVerified) while failing to satisfy
// RequireIndependent.
func TestEarlierPrefixWitnessDoesNotMakeTheExportIndependent(t *testing.T) {
	entries, head, pub, leaves := buildLog(t, 6)
	wpub, wpriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// The head the witness actually saw: the tree as of 3 entries, signed by
	// the ledger's own key the way a real anchor would be.
	prefixHead := hash.TreeHead{
		LogID:    head.LogID,
		Index:    entries[2].Sequence,
		RootHash: hash.MerkleRoot(leaves[:3]),
		TreeSize: 3,
		SignedAt: head.SignedAt,
	}
	prefixHead.Signature = ed25519.Sign(testPriv(), HeadPayload(prefixHead))
	w := WitnessView{
		WitnessID: "ext-1",
		PublicKey: wpub,
		Signature: ed25519.Sign(wpriv, HeadPayload(prefixHead)),
		SignedAt:  prefixHead.SignedAt,
		KeyHolder: "external",
	}
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: prefixHead, Witnesses: []WitnessView{w}}})
	opts := VerifyOptions{RequireIndependent: true, TrustedWitnessKeys: map[string][]byte{"ext-1": wpub}}
	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("an export whose only witness cosignature covers an earlier prefix passed independent verification: %+v", res)
	}
	if res.WitnessesVerified != 1 {
		t.Fatalf("WitnessesVerified = %d, want the prefix cosignature to stay visible", res.WitnessesVerified)
	}
	if res.IndependentWitnesses != 0 {
		t.Fatalf("IndependentWitnesses = %d, want 0 for an earlier-prefix cosignature", res.IndependentWitnesses)
	}
	joined := strings.Join(res.Warnings, " ") + " " + strings.Join(res.Errors, " ")
	if !strings.Contains(joined, "earlier prefix") {
		t.Fatalf("the report does not say the cosignature covers an earlier prefix: warnings=%v errors=%v", res.Warnings, res.Errors)
	}
}

// A tree_size 0 anchor commits to no entries, and its root is the SAME
// constant for every log — so a witnessed empty-head anchor from any log run
// under the same signing key used to count as independent evidence here. It
// must be rejected outright and its witnesses not counted, even when the
// witness key is pinned as trusted out of band.
func TestSizeZeroAnchorIsRejectedAndNeverCountsWitnesses(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 4)
	emptyHead := hash.TreeHead{
		LogID:    head.LogID,
		RootHash: hash.MerkleRoot(nil), // the empty-tree constant every log shares
		SignedAt: head.SignedAt,
	}
	emptyHead.Signature = ed25519.Sign(testPriv(), HeadPayload(emptyHead))
	wpub, wpriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	w := WitnessView{
		WitnessID: "ext-1",
		PublicKey: wpub,
		Signature: ed25519.Sign(wpriv, HeadPayload(emptyHead)),
		SignedAt:  emptyHead.SignedAt,
		KeyHolder: "external",
	}
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: emptyHead, Witnesses: []WitnessView{w}}})
	opts := VerifyOptions{RequireIndependent: true, TrustedWitnessKeys: map[string][]byte{"ext-1": wpub}}
	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("an export with a tree_size 0 anchor verified: %+v", res)
	}
	if res.AnchorsOK {
		t.Fatal("anchors_ok stayed true for a tree_size 0 anchor")
	}
	if res.IndependentWitnesses != 0 || res.WitnessesVerified != 0 {
		t.Fatalf("witnesses on a size-0 anchor were counted: verified=%d independent=%d", res.WitnessesVerified, res.IndependentWitnesses)
	}
	if !strings.Contains(strings.Join(res.Errors, " "), "tree_size 0") {
		t.Fatalf("the refusal does not name the empty anchor: %v", res.Errors)
	}
}

func TestTimestampIndependenceRequiresTSARootsAndCMS(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 3)
	digest := sha256.Sum256(HeadPayload(head))
	certDER, cert, pool, key := testTSA(t)
	_ = certDER
	tok := signedTSToken(t, digest[:], cert, key)
	anchor := AnchorView{
		Head: head,
		Timestamp: &TimestampView{
			Authority: "canary",
			Digest:    hex.EncodeToString(digest[:]),
			Time:      testTSGenTime,
			Token:     tok,
		},
	}
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{anchor})

	without := func() *Result {
		res, err := VerifyExportReader(strings.NewReader(doc), pub)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}()
	if !without.OK {
		t.Fatalf("without roots, OK should stay true: %v", without.Errors)
	}
	if without.TimestampsIndependent != 0 {
		t.Fatalf("without TSA roots TimestampsIndependent = %d, want 0", without.TimestampsIndependent)
	}

	with, err := VerifyExportReaderWithTrust(strings.NewReader(doc), pub, pool)
	if err != nil {
		t.Fatal(err)
	}
	if !with.OK {
		t.Fatalf("with roots the export did not verify: %v", with.Errors)
	}
	if with.TimestampsIndependent != 1 {
		t.Fatalf("with verifying CMS token TimestampsIndependent = %d, want 1 (warnings %v)", with.TimestampsIndependent, with.Warnings)
	}
}

func testTSA(t *testing.T) ([]byte, *x509.Certificate, *x509.CertPool, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "verifier-tsa"},
		NotBefore:             testTSGenTime.Add(-24 * time.Hour),
		NotAfter:              testTSGenTime.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return der, cert, pool, key
}

func signedTSToken(t *testing.T, digest []byte, cert *x509.Certificate, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	tstDER, err := asn1.Marshal(tsInfo{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59999, 1, 1},
		MessageImprint: tsImprint{
			HashAlgorithm: tsAlgID{Algorithm: oidSHA256Verifier},
			HashedMessage: digest,
		},
		SerialNumber: big.NewInt(7),
		GenTime:      testTSGenTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	hashed := sha256.Sum256(tstDER)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hashed[:])
	if err != nil {
		t.Fatal(err)
	}
	sid, err := asn1.Marshal(struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}{Issuer: asn1.RawValue{FullBytes: cert.RawIssuer}, SerialNumber: cert.SerialNumber})
	if err != nil {
		t.Fatal(err)
	}
	siDER, err := asn1.Marshal(tsSignerInfo{
		Version:            1,
		SID:                asn1.RawValue{FullBytes: sid},
		DigestAlgorithm:    tsAlgID{Algorithm: oidSHA256Verifier},
		SignatureAlgorithm: tsAlgID{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		Signature:          sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	algDER, err := asn1.Marshal(tsAlgID{Algorithm: oidSHA256Verifier})
	if err != nil {
		t.Fatal(err)
	}
	setDER, err := asn1.Marshal([]asn1.RawValue{{FullBytes: cert.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	var set asn1.RawValue
	if _, err := asn1.Unmarshal(setDER, &set); err != nil {
		t.Fatal(err)
	}
	sdDER, err := asn1.Marshal(tsSignedData{
		Version:          3,
		DigestAlgorithms: asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: algDER},
		EncapContentInfo: tsEncap{EContentType: oidTSTInfoVerifier, EContent: tstDER},
		Certificates:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: set.Bytes},
		SignerInfos:      asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: siDER},
	})
	if err != nil {
		t.Fatal(err)
	}
	ciDER, err := asn1.Marshal(tsContentInfo{
		ContentType: oidSignedDataVerifier,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sdDER},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := asn1.Marshal(tsResp{
		Status:         tsPKIStatus{Status: pkiGranted},
		TimeStampToken: asn1.RawValue{FullBytes: ciDER},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
