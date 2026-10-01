package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

type errAfter struct {
	r     io.Reader
	errAt int
	n     int
}

func (e *errAfter) Read(p []byte) (int, error) {
	if e.n >= e.errAt {
		return 0, errors.New("boom")
	}
	if remain := e.errAt - e.n; len(p) > remain {
		p = p[:remain]
	}
	n, err := e.r.Read(p)
	e.n += n
	if e.n >= e.errAt {
		return n, errors.New("boom")
	}
	return n, err
}

func TestLoadExportAndVerifyExportPaths(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 3)
	doc := exportJSONL(t, entries, head, pub)
	dir := t.TempDir()
	path := filepath.Join(dir, "export.jsonl")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	exp, err := LoadExport(path)
	if err != nil || exp.Path != path || len(exp.Entries) != 3 {
		t.Fatalf("LoadExport = %+v %v", exp, err)
	}
	res, err := VerifyExportWithOptions(path, pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil || !res.OK || res.Path != path {
		t.Fatalf("VerifyExport = %+v %v", res, err)
	}
	if _, err := LoadExport(filepath.Join(dir, "missing.jsonl")); err == nil {
		t.Fatal("LoadExport accepted a missing file")
	}
	badPath := filepath.Join(dir, "bad.jsonl")
	if err := os.WriteFile(badPath, []byte("this is not an export\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExport(badPath); err == nil || !errors.Is(err, ErrMalformed) {
		t.Fatalf("LoadExport of garbage = %v", err)
	}
	res, err = VerifyExport(filepath.Join(dir, "missing.jsonl"), pub)
	if err == nil || res == nil || res.OK {
		t.Fatalf("VerifyExport missing file = %+v %v", res, err)
	}
	_, cert, pool, key := testTSA(t)
	digest := sha256.Sum256(HeadPayload(head))
	tok := signedTSToken(t, digest[:], cert, key)
	withTS := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{
		Head: head,
		Timestamp: &TimestampView{
			Authority: "canary", Digest: hex.EncodeToString(digest[:]),
			Time: testTSGenTime, Token: tok,
		},
	}})
	tsPath := filepath.Join(dir, "with-ts.jsonl")
	if err := os.WriteFile(tsPath, []byte(withTS), 0o600); err != nil {
		t.Fatal(err)
	}
	trusted, err := VerifyExportWithTrust(tsPath, pub, pool)
	if err != nil || !trusted.OK || trusted.TimestampsIndependent != 1 {
		t.Fatalf("VerifyExportWithTrust = %+v %v", trusted, err)
	}

	if _, err := LoadExportReader(&errAfter{r: strings.NewReader(doc), errAt: 12}); err == nil || !errors.Is(err, ErrMalformed) {
		t.Fatalf("short read = %v", err)
	}
}

func TestLoadExportReaderShapeRefusals(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	doc := exportJSONL(t, entries, head, pub)
	lines := strings.Split(strings.TrimRight(doc, "\n"), "\n")
	header, entry := lines[0], lines[1]
	blank := header + "\n\n" + strings.Join(lines[1:], "\n") + "\n"
	exp, err := LoadExportReader(strings.NewReader(blank))
	if err != nil || len(exp.Entries) != 2 {
		t.Fatalf("blank lines = %+v %v", exp, err)
	}
	lateHeader := entry + "\n" + header + "\n"
	if _, err := LoadExportReader(strings.NewReader(lateHeader)); err == nil || !errors.Is(err, ErrMalformed) {
		t.Fatalf("header after entry = %v", err)
	}
}

func TestParsePublicKeyAndSeedEncodings(t *testing.T) {
	pub := testPub()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	if got, err := ParsePublicKey("ed25519:" + hex.EncodeToString(pub)); err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("prefixed hex = %v %v", got, err)
	}
	if got, err := ParsePublicKey(base64.StdEncoding.EncodeToString(pub)); err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("std base64 = %v %v", got, err)
	}
	if got, err := ParsePublicKey(base64.RawStdEncoding.EncodeToString(pub)); err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("raw base64 = %v %v", got, err)
	}
	if got, err := ParseSeed(base64.StdEncoding.EncodeToString(seed)); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("seed std base64 = %v %v", got, err)
	}
	if got, err := ParseSeed(base64.RawStdEncoding.EncodeToString(seed)); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("seed raw base64 = %v %v", got, err)
	}
	if _, err := ParsePublicKey(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("short base64 public key was accepted")
	}
	leak := "PEM-LOOKING-PRIVATE-MATERIAL-do-not-echo"
	if _, err := ParsePublicKey(leak); err == nil {
		t.Fatal("garbage public key was accepted")
	} else if strings.Contains(err.Error(), leak) {
		t.Fatalf("public-key parse error echoed the input: %v", err)
	}
	if _, err := ParseSeed("not-a-seed"); err == nil {
		t.Fatal("garbage seed was accepted")
	}
}

func TestResultHelpersAndEmbeddedKey(t *testing.T) {
	r := &Result{}
	for i := 0; i < 27; i++ {
		r.addError("e%d", i)
	}
	if len(r.Errors) != maxReportedErrors+1 || r.Errors[maxReportedErrors] != "... further errors truncated" {
		t.Fatalf("addError truncation = %#v", r.Errors)
	}
	entries, head, pub, _ := buildLog(t, 2)
	doc := exportJSONL(t, entries, head, pub)
	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), nil, VerifyOptions{AllowPreAnchor: true})
	if err != nil || !res.OK || res.KeySource != "embedded" {
		t.Fatalf("embedded key = %+v %v", res, err)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "embedded") {
		t.Fatalf("embedded-key warning missing: %v", res.Warnings)
	}
	raw, err := MarshalResult(res)
	if err != nil || (!bytes.Contains(raw, []byte(`"ok": true`)) && !bytes.Contains(raw, []byte(`"ok":true`))) {
		t.Fatalf("MarshalResult = %s %v", raw, err)
	}

	badKey := strings.Replace(doc, `"public_key":"`+hex.EncodeToString(pub)+`"`, `"public_key":"zzzz"`, 1)
	res, err = VerifyExportReaderWithOptions(strings.NewReader(badKey), nil, VerifyOptions{AllowPreAnchor: true})
	if err != nil || res.OK {
		t.Fatalf("bad embedded key = %+v %v", res, err)
	}
	if !strings.Contains(strings.Join(res.Errors, " "), "key") && !strings.Contains(strings.Join(res.Errors, " "), "public") {
		t.Fatalf("bad-key refusal does not name the key: %v", res.Errors)
	}

	wrongSchema := strings.Replace(doc, ExportSchema, "aaes.export/v0", 1)
	res, err = VerifyExportReaderWithOptions(strings.NewReader(wrongSchema), pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil || res.OK || !strings.Contains(strings.Join(res.Errors, " "), "schema") {
		t.Fatalf("wrong schema = %+v %v", res, err)
	}
	count := strings.Replace(doc, `"entry_count":2`, `"entry_count":9`, 1)
	res, err = VerifyExportReaderWithOptions(strings.NewReader(count), pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil || res.OK || !strings.Contains(strings.Join(res.Errors, " "), "declares") {
		t.Fatalf("entry count = %+v %v", res, err)
	}
}

func TestChainAndReceiptRemainingRefusals(t *testing.T) {
	entries, head, pub, leaves := buildLog(t, 4)
	missingTenant := append([]EntryView(nil), entries...)
	missingTenant[0].TenantID = ""
	st := checkChain(missingTenant, head, pub)
	if st.chainErr == nil {
		t.Fatal("missing tenant_id did not fail the chain")
	}

	bad := entries[0]
	bad.AmountMinor++
	st = checkChain([]EntryView{bad, entries[1]}, head, pub)
	if st.chainErr == nil {
		t.Fatal("tampered amount did not fail the chain")
	}

	noChain := entries[0]
	noChain.ChainHash = ""
	st = checkChain([]EntryView{noChain}, hash.TreeHead{TreeSize: 1, RootHash: noChain.Leaf, Index: 1}, pub)
	if st.chainErr == nil || !strings.Contains(st.chainErr.Error(), "missing chain_hash") {
		t.Fatalf("missing chain_hash = %v", st.chainErr)
	}
	noLeaf := entries[0]
	noLeaf.Leaf = ""
	st = checkChain([]EntryView{noLeaf}, hash.TreeHead{TreeSize: 1, RootHash: entries[0].Leaf, Index: 1}, pub)
	if st.chainErr == nil || !strings.Contains(st.chainErr.Error(), "missing leaf") {
		t.Fatalf("missing leaf = %v", st.chainErr)
	}

	gap := []EntryView{entries[0], entries[2]}
	pre1, _ := gap[0].preimage()
	pre2, _ := gap[1].preimage()
	gap[0].ChainHash = hash.Chain("", pre1)
	gap[0].Leaf = hash.SHA256Hex(pre1)
	gap[1].ChainHash = hash.Chain(gap[0].ChainHash, pre2)
	gap[1].Leaf = hash.SHA256Hex(pre2)
	gLeaves := []string{gap[0].Leaf, gap[1].Leaf}
	gHead := hash.TreeHead{Index: gap[1].Sequence, RootHash: hash.MerkleRoot(gLeaves), TreeSize: 2, SignedAt: head.SignedAt}
	gHead.Signature = ed25519.Sign(testPriv(), HeadPayload(gHead))
	st = checkChain(gap, gHead, pub)
	if st.chainErr != nil || st.contiguous || len(st.entryErrors) != 0 {
		t.Fatalf("non-contiguous = %+v", st)
	}

	wrongIndex := head
	wrongIndex.Index = 99
	wrongIndex.Signature = ed25519.Sign(testPriv(), HeadPayload(wrongIndex))
	if err := VerifyChain(entries, wrongIndex, pub); err == nil || !errors.Is(err, ErrRoot) {
		t.Fatalf("head index mismatch = %v", err)
	}

	if err := VerifyTreeHead(head, []byte("short")); !errors.Is(err, ErrSignature) {
		t.Fatalf("short public key = %v", err)
	}

	seq0 := entries[0]
	seq0.Sequence = 0
	pre, _ := seq0.preimage()
	seq0.ChainHash = hash.Chain("", pre)
	seq0.Leaf = hash.SHA256Hex(pre)
	s0head := hash.TreeHead{Index: 0, RootHash: hash.MerkleRoot([]string{seq0.Leaf}), TreeSize: 1, SignedAt: head.SignedAt}
	s0head.Signature = ed25519.Sign(testPriv(), HeadPayload(s0head))
	doc := exportJSONL(t, []EntryView{seq0}, s0head, pub)
	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil || res.OK || !strings.Contains(strings.Join(res.Errors, " "), "sequence 0") {
		t.Fatalf("sequence 0 = %+v %v", res, err)
	}

	proof, err := hash.ProveInclusion(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}
	entry := entries[1]
	r := ReceiptView{
		ReceiptID: "r", TenantID: entry.TenantID, IntentID: entry.IntentID, RecordHash: entry.RecordHash,
		IssuedAt: entry.OccurredAt, Entry: &entry, Leaf: entry.Leaf, Proof: &proof, Head: &head,
	}
	if err := VerifyReceipt(ReceiptView{}, pub); !errors.Is(err, ErrReceipt) {
		t.Fatalf("empty receipt = %v", err)
	}
	if err := VerifyReceipt(r, nil); !errors.Is(err, ErrNoPublicKey) {
		t.Fatalf("no key = %v", err)
	}
	noLeafR := r
	noLeafR.Leaf = ""
	if err := VerifyReceipt(noLeafR, pub); !errors.Is(err, ErrReceipt) {
		t.Fatalf("no leaf = %v", err)
	}
	bigProof := r
	p := proof
	p.TreeSize = head.TreeSize + 1
	bigProof.Proof = &p
	if err := VerifyReceipt(bigProof, pub); !errors.Is(err, ErrReceipt) {
		t.Fatalf("proof larger than head = %v", err)
	}
	rootProof := r
	p = proof
	p.RootHash = hash.SHA256Hex([]byte("other"))
	rootProof.Proof = &p
	if err := VerifyReceipt(rootProof, pub); !errors.Is(err, ErrReceipt) {
		t.Fatalf("proof root mismatch = %v", err)
	}
	wrongTenant := r
	e := entry
	e.TenantID = "other"
	wrongTenant.Entry = &e
	if err := VerifyReceipt(wrongTenant, pub); !errors.Is(err, ErrReceipt) {
		t.Fatalf("tenant mismatch = %v", err)
	}
	wrongIntent := r
	e = entry
	e.IntentID = "other-intent"
	wrongIntent.Entry = &e
	if err := VerifyReceipt(wrongIntent, pub); !errors.Is(err, ErrReceipt) {
		t.Fatalf("intent mismatch = %v", err)
	}
	wrongHash := r
	e = entry
	e.RecordHash = "other-hash"
	wrongHash.Entry = &e
	if err := VerifyReceipt(wrongHash, pub); !errors.Is(err, ErrReceipt) {
		t.Fatalf("record hash mismatch = %v", err)
	}
	nanEntry := r
	e = entry
	e.AmountMinor = 1
	e.AmountCurrency = ""
	nanEntry.Entry = &e
	if err := VerifyReceipt(nanEntry, pub); err == nil {
		t.Fatal("invalid amount entry attached to a receipt verified")
	}
	wrongLeaf := r
	e = entry
	e.AmountMinor = entry.AmountMinor + 1
	wrongLeaf.Entry = &e
	wrongLeaf.Leaf = entry.Leaf
	if err := VerifyReceipt(wrongLeaf, pub); !errors.Is(err, ErrReceipt) {
		t.Fatalf("recomputed leaf mismatch = %v", err)
	}
}

func TestVerifyParsedAnchorWitnessAndTimestampGaps(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 4)
	digest := sha256.Sum256(HeadPayload(head))

	badSig := head
	badSig.Signature = append([]byte(nil), head.Signature...)
	badSig.Signature[0] ^= 0xff
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: badSig}})
	res, err := VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil || res.OK || res.AnchorsOK {
		t.Fatalf("bad anchor signature = %+v %v", res, err)
	}

	tooBig := head
	tooBig.TreeSize = 99
	tooBig.Signature = ed25519.Sign(testPriv(), HeadPayload(tooBig))
	doc = exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: tooBig}})
	res, err = VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil || res.OK || !strings.Contains(strings.Join(res.Errors, " "), "covers") {
		t.Fatalf("oversized anchor = %+v %v", res, err)
	}

	wrongRoot := head
	wrongRoot.RootHash = hash.SHA256Hex([]byte("nope"))
	wrongRoot.TreeSize = 2
	wrongRoot.Index = entries[1].Sequence
	wrongRoot.Signature = ed25519.Sign(testPriv(), HeadPayload(wrongRoot))
	doc = exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: wrongRoot}})
	res, err = VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil || res.OK || !strings.Contains(strings.Join(res.Errors, " "), "is not the root") {
		t.Fatalf("wrong prefix root = %+v %v", res, err)
	}

	doc = exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{
		Head: head,
		Timestamp: &TimestampView{
			Authority: "tsa", Digest: hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
			Time: head.SignedAt, Token: []byte{0x30, 0x00},
		},
	}})
	res, err = VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil || res.OK || !strings.Contains(strings.Join(res.Errors, " "), "does not cover this head") {
		t.Fatalf("timestamp digest = %+v %v", res, err)
	}

	_, cert, _, key := testTSA(t)
	tok := signedTSToken(t, digest[:], cert, key)
	doc = exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{
		Head: head,
		Timestamp: &TimestampView{
			Authority: "tsa", Digest: hex.EncodeToString(digest[:]),
			Time: testTSGenTime, Token: tok,
		},
	}})
	otherPool := x509.NewCertPool()
	res, err = VerifyExportReaderWithTrust(strings.NewReader(doc), pub, otherPool)
	if err != nil || res.TimestampsIndependent != 0 || !strings.Contains(strings.Join(res.Warnings, " "), "not independent") && !strings.Contains(strings.Join(res.Warnings, " "), "supplied TSA roots") {
		t.Fatalf("untrusted TSA = %+v %v", res, err)
	}

	wpub, wpriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	goodSig := ed25519.Sign(wpriv, HeadPayload(head))
	doc = exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{
		Head: head,
		Witnesses: []WitnessView{
			{WitnessID: "empty"},
			{WitnessID: "nokey", Signature: goodSig},
			{WitnessID: "bad", PublicKey: wpub, Signature: bytes.Repeat([]byte{1}, ed25519.SignatureSize)},
			{WitnessID: "aaes-held", PublicKey: wpub, Signature: goodSig, KeyHolder: "aes-held"},
		},
		Timestamp: &TimestampView{Authority: "noop", Digest: hex.EncodeToString(digest[:]), Noop: true, Time: head.SignedAt},
	}})
	res, err = VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("broken witnesses verified: %+v", res)
	}
	joined := strings.Join(res.Errors, " ")
	if !strings.Contains(joined, "no verifiable public key") || !strings.Contains(joined, "does not verify") {
		t.Fatalf("witness errors = %v", res.Errors)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "noop placeholder") {
		t.Fatalf("noop timestamp warning missing: %v", res.Warnings)
	}

	doc = exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{
		Head:      head,
		Witnesses: []WitnessView{{WitnessID: "aaes-held", PublicKey: wpub, Signature: goodSig, KeyHolder: "aes-held"}},
	}})
	res, err = VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil || !res.OK {
		t.Fatalf("AAES-held witness = %+v %v", res, err)
	}
	if res.WitnessesVerified != 1 || res.IndependentWitnesses != 0 {
		t.Fatalf("AAES-held counted as independent: %+v", res)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "none matches a trusted independent witness key") {
		t.Fatalf("non-independent witness warning missing: %v", res.Warnings)
	}
}

func TestTimestampCMSHelpers(t *testing.T) {
	if err := verifyTimestampWithTrust(TimestampView{}, nil, time.Time{}); err == nil {
		t.Fatal("nil roots were accepted")
	}
	if err := verifyTimestampWithTrust(TimestampView{Noop: true}, x509.NewCertPool(), time.Time{}); err == nil {
		t.Fatal("noop timestamp was trusted")
	}
	if err := verifyTimestampWithTrust(TimestampView{}, x509.NewCertPool(), time.Time{}); err == nil {
		t.Fatal("empty token was trusted")
	}

	if err := verifyTimestampWithTrust(TimestampView{Token: []byte("nope")}, x509.NewCertPool(), time.Time{}); err == nil {
		t.Fatal("garbage token was trusted")
	}

	at := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	digest := bytes.Repeat([]byte{9}, 32)
	if _, _, err := parseTimestampCMS([]byte("nope")); err == nil {
		t.Fatal("garbage CMS parsed")
	}
	if _, _, err := parseTimestampCMS(append(tsStructureResponse(t, tsStructureContentInfo(t, oidSignedDataVerifier, tsStructureSignedData(t, oidTSTInfoVerifier, tsStructureTSTInfo(t, oidSHA256Verifier, digest, at))), pkiGranted), 0x00)); err == nil {
		t.Fatal("trailing response parsed")
	}
	if _, _, err := parseTimestampCMS(tsStructureResponseStatus(t, 2)); err == nil {
		t.Fatal("rejected PKIStatus parsed")
	}
	if _, _, err := parseTimestampCMS(tsStructureResponse(t, nil, pkiGranted)); err == nil {
		t.Fatal("granted without token parsed")
	}
	if _, _, err := parseTimestampCMS(tsStructureResponse(t, mustASN1(t, big.NewInt(1)), pkiGranted)); err == nil {
		t.Fatal("token not ContentInfo parsed")
	}
	if _, _, err := parseTimestampCMS(tsStructureResponse(t, tsStructureContentInfo(t, asn1.ObjectIdentifier{1, 2, 3}, []byte{0x30, 0x00}), pkiGranted)); err == nil {
		t.Fatal("not signedData parsed")
	}
	if _, _, err := parseTimestampCMS(tsStructureResponse(t, tsStructureContentInfo(t, oidSignedDataVerifier, []byte{0x01}), pkiGranted)); err == nil {
		t.Fatal("bad SignedData parsed")
	}
	if _, _, err := parseTimestampCMS(tsStructureResponse(t, tsStructureContentInfo(t, oidSignedDataVerifier, tsStructureSignedData(t, asn1.ObjectIdentifier{1, 2, 3}, []byte{0x30, 0x00})), pkiGranted)); err == nil {
		t.Fatal("not TSTInfo parsed")
	}
	if _, _, err := parseTimestampCMS(tsStructureResponse(t, tsStructureContentInfo(t, oidSignedDataVerifier, tsStructureSignedData(t, oidTSTInfoVerifier, nil)), pkiGranted)); err == nil {
		t.Fatal("absent TSTInfo parsed")
	}
	if _, _, err := parseTimestampCMS(tsStructureResponse(t, tsStructureContentInfo(t, oidSignedDataVerifier, tsStructureSignedData(t, oidTSTInfoVerifier, []byte{0x01})), pkiGranted)); err == nil {
		t.Fatal("bad TSTInfo parsed")
	}

	sha1 := tsStructureResponse(t, tsStructureContentInfo(t, oidSignedDataVerifier, tsStructureSignedData(t, oidTSTInfoVerifier, tsStructureTSTInfo(t, asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, digest, at))), pkiGranted)
	if err := verifyTimestampWithTrust(TimestampView{Digest: hex.EncodeToString(digest), Token: sha1}, x509.NewCertPool(), time.Time{}); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("SHA-1 imprint = %v", err)
	}
	okTok := tsStructureResponse(t, tsStructureContentInfo(t, oidSignedDataVerifier, tsStructureSignedData(t, oidTSTInfoVerifier, tsStructureTSTInfo(t, oidSHA256Verifier, digest, at))), pkiGranted)
	if err := verifyTimestampWithTrust(TimestampView{Digest: hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), Token: okTok}, x509.NewCertPool(), time.Time{}); err == nil || !strings.Contains(err.Error(), "not") {
		t.Fatalf("imprint mismatch = %v", err)
	}
	if err := verifyTimestampWithTrust(TimestampView{Digest: hex.EncodeToString(digest), Token: okTok, Time: at}, x509.NewCertPool(), time.Time{}); err == nil || !strings.Contains(err.Error(), "no signer certificate") {
		t.Fatalf("no cert = %v", err)
	}

	garbageBag := tsStructureResponse(t, tsStructureContentInfo(t, oidSignedDataVerifier, mustASN1(t, tsSignedData{
		Version: 3, DigestAlgorithms: asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: mustASN1(t, tsAlgID{Algorithm: oidSHA256Verifier})},
		EncapContentInfo: tsEncap{EContentType: oidTSTInfoVerifier, EContent: tsStructureTSTInfo(t, oidSHA256Verifier, digest, at)},
		Certificates:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{0x01, 0x02}},
		SignerInfos:      asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: nil},
	})), pkiGranted)
	if err := verifyTimestampWithTrust(TimestampView{Digest: hex.EncodeToString(digest), Token: garbageBag}, x509.NewCertPool(), time.Time{}); err == nil {
		t.Fatal("garbage certificate bag was trusted")
	}

	der, cert, pool, key := testTSA(t)
	withCertNoSI := tsStructureResponse(t, tsStructureContentInfo(t, oidSignedDataVerifier, mustASN1(t, tsSignedData{
		Version: 3, DigestAlgorithms: asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: mustASN1(t, tsAlgID{Algorithm: oidSHA256Verifier})},
		EncapContentInfo: tsEncap{EContentType: oidTSTInfoVerifier, EContent: tsStructureTSTInfo(t, oidSHA256Verifier, digest, at)},
		Certificates:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: der},
		SignerInfos:      asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: nil},
	})), pkiGranted)
	if err := verifyTimestampWithTrust(TimestampView{Digest: hex.EncodeToString(digest), Token: withCertNoSI}, pool, time.Time{}); err == nil {
		t.Fatal("a certificate without SignerInfos was trusted")
	}

	if got, err := tsCertificates(asn1.RawValue{}); err != nil || got != nil {
		t.Fatalf("empty certs = %v %v", got, err)
	}
	got, err := tsCertificates(asn1.RawValue{Bytes: der})
	if err != nil || len(got) != 1 {
		t.Fatalf("single cert = %v %v", got, err)
	}
	if _, err := tsCertificates(asn1.RawValue{Bytes: []byte{0x01, 0x02}}); err == nil {
		t.Fatal("garbage cert field accepted")
	}
	der2, _, _, _ := testTSA(t)
	got, err = tsCertificates(asn1.RawValue{Bytes: append(append([]byte(nil), der...), der2...)})
	if err != nil || len(got) != 2 {
		t.Fatalf("cert SET = %d %v", len(got), err)
	}

	if _, err := tsParseSignerInfos(asn1.RawValue{}); err == nil {
		t.Fatal("empty SignerInfos accepted")
	}
	if _, err := tsParseSignerInfos(asn1.RawValue{Bytes: []byte{0x01}}); err == nil {
		t.Fatal("garbage SignerInfo accepted")
	}
	emptySI := mustASN1(t, tsSignerInfo{
		Version: 1, SID: asn1.RawValue{FullBytes: mustASN1(t, big.NewInt(1))},
		DigestAlgorithm:    tsAlgID{Algorithm: oidSHA256Verifier},
		SignatureAlgorithm: tsAlgID{Algorithm: oidSHA256Verifier},
	})
	if _, err := tsParseSignerInfos(asn1.RawValue{Bytes: emptySI}); err == nil {
		t.Fatal("SignerInfo without signature accepted")
	}

	if _, err := tsVerifyCMS(tsSignedData{SignerInfos: asn1.RawValue{Bytes: mustASN1(t, tsSignerInfo{
		Version: 1, SID: asn1.RawValue{FullBytes: mustASN1(t, big.NewInt(1))},
		DigestAlgorithm: tsAlgID{Algorithm: oidSHA256Verifier}, SignatureAlgorithm: tsAlgID{Algorithm: oidSHA256Verifier},
		Signature: []byte("x"),
	})}, EncapContentInfo: tsEncap{EContent: []byte("x")}}, [][]byte{[]byte("not-a-cert")}); err == nil {
		t.Fatal("unparseable CMS cert accepted")
	}
	siNoMatch := mustASN1(t, tsSignerInfo{
		Version: 1, Signature: []byte("x"),
		DigestAlgorithm: tsAlgID{Algorithm: oidSHA256Verifier}, SignatureAlgorithm: tsAlgID{Algorithm: oidSHA256Verifier},
		SID: asn1.RawValue{FullBytes: mustASN1(t, big.NewInt(1))},
	})
	if _, err := tsVerifyCMS(tsSignedData{EncapContentInfo: tsEncap{EContent: []byte("x")}, SignerInfos: asn1.RawValue{Bytes: siNoMatch}}, [][]byte{der}); err == nil {
		t.Fatal("unmatched SignerInfo verified")
	}

	skidCert := *cert
	skidCert.SubjectKeyId = []byte{8, 8, 8, 8}
	if tsMatchSigner(tsSignerInfo{SID: asn1.RawValue{Class: 2, Tag: 0, Bytes: []byte{8, 8, 8, 8}}}, []*x509.Certificate{&skidCert}) == nil {
		t.Fatal("SKID match missed")
	}
	if tsMatchSigner(tsSignerInfo{SID: asn1.RawValue{Class: 2, Tag: 0, Bytes: []byte("nope")}}, []*x509.Certificate{cert}) != nil {
		t.Fatal("SKID mismatch matched")
	}

	if _, err := tsSigAlg(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, cert.PublicKey); err == nil {
		t.Fatal("SHA-1 sig alg accepted")
	}
	if _, err := tsSigAlg(oidSHA256Verifier, struct{}{}); err == nil {
		t.Fatal("unknown key type accepted")
	}
	if algo, err := tsSigAlg(oidSHA256Verifier, cert.PublicKey); err != nil || algo != x509.ECDSAWithSHA256 {
		t.Fatalf("ECDSA alg = %v %v", algo, err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if algo, err := tsSigAlg(oidSHA256Verifier, &rsaKey.PublicKey); err != nil || algo != x509.SHA256WithRSA {
		t.Fatalf("RSA alg = %v %v", algo, err)
	}
	edPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if algo, err := tsSigAlg(oidSHA256Verifier, edPub); err != nil || algo != x509.PureEd25519 {
		t.Fatalf("Ed25519 alg = %v %v", algo, err)
	}

	if err := tsCheckMessageDigest([]byte{0x01}, []byte("x")); err == nil {
		t.Fatal("garbage signedAttrs accepted")
	}
	other := mustASN1(t, struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}{Type: oidSHA256Verifier, Values: []asn1.RawValue{{FullBytes: mustASN1(t, []byte("x"))}}})
	if err := tsCheckMessageDigest(other, []byte("x")); err == nil {
		t.Fatal("missing message-digest accepted")
	}
	emptyVal := mustASN1(t, struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}{Type: oidMessageDigestV})
	if err := tsCheckMessageDigest(emptyVal, []byte("x")); err == nil {
		t.Fatal("empty message-digest accepted")
	}
	notOctet := mustASN1(t, struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}{Type: oidMessageDigestV, Values: []asn1.RawValue{{FullBytes: mustASN1(t, 1)}}})
	if err := tsCheckMessageDigest(notOctet, []byte("x")); err == nil {
		t.Fatal("non-octet message-digest accepted")
	}
	sum := sha256.Sum256([]byte("other"))
	wrong := mustASN1(t, struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}{Type: oidMessageDigestV, Values: []asn1.RawValue{{FullBytes: mustASN1(t, sum[:])}}})
	if err := tsCheckMessageDigest(wrong, []byte("x")); err == nil {
		t.Fatal("mismatched message-digest accepted")
	}
	goodSum := sha256.Sum256([]byte("x"))
	good := mustASN1(t, struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}{Type: oidMessageDigestV, Values: []asn1.RawValue{{FullBytes: mustASN1(t, goodSum[:])}}})
	if err := tsCheckMessageDigest(good, []byte("x")); err != nil {
		t.Fatalf("matching message-digest refused: %v", err)
	}

	eContent := []byte("verifier-tst")
	md := sha256.Sum256(eContent)
	mdAttr := mustASN1(t, struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}{Type: oidMessageDigestV, Values: []asn1.RawValue{{FullBytes: mustASN1(t, md[:])}}})
	setToSign := mustASN1(t, asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: mdAttr})
	hashed := sha256.Sum256(setToSign)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hashed[:])
	if err != nil {
		t.Fatal(err)
	}
	sid := mustASN1(t, struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}{Issuer: asn1.RawValue{FullBytes: cert.RawIssuer}, SerialNumber: cert.SerialNumber})
	signedSI := mustASN1(t, tsSignerInfo{
		Version: 1, SID: asn1.RawValue{FullBytes: sid},
		DigestAlgorithm:    tsAlgID{Algorithm: oidSHA256Verifier},
		SignedAttrs:        asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: mdAttr},
		SignatureAlgorithm: tsAlgID{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		Signature:          sig,
	})
	gotCert, err := tsVerifyCMS(tsSignedData{
		EncapContentInfo: tsEncap{EContent: eContent},
		SignerInfos:      asn1.RawValue{Bytes: signedSI},
	}, [][]byte{der})
	if err != nil || gotCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("signedAttrs CMS = %v %v", gotCert, err)
	}
	flipped := append([]byte(nil), sig...)
	flipped[0] ^= 0xff
	badSI := mustASN1(t, tsSignerInfo{
		Version: 1, SID: asn1.RawValue{FullBytes: sid},
		DigestAlgorithm:    tsAlgID{Algorithm: oidSHA256Verifier},
		SignedAttrs:        asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: mdAttr},
		SignatureAlgorithm: tsAlgID{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		Signature:          flipped,
	})
	if _, err := tsVerifyCMS(tsSignedData{EncapContentInfo: tsEncap{EContent: eContent}, SignerInfos: asn1.RawValue{Bytes: badSI}}, [][]byte{der}); err == nil {
		t.Fatal("flipped CMS signature verified")
	}
	sha1SI := mustASN1(t, tsSignerInfo{
		Version: 1, SID: asn1.RawValue{FullBytes: sid},
		DigestAlgorithm:    tsAlgID{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}},
		SignatureAlgorithm: tsAlgID{Algorithm: oidSHA256Verifier},
		Signature:          []byte("x"),
	})
	if _, err := tsVerifyCMS(tsSignedData{EncapContentInfo: tsEncap{EContent: eContent}, SignerInfos: asn1.RawValue{Bytes: sha1SI}}, [][]byte{der}); err == nil {
		t.Fatal("SHA-1 SignerInfo verified")
	}
	missingMD := mustASN1(t, tsSignerInfo{
		Version: 1, SID: asn1.RawValue{FullBytes: sid},
		DigestAlgorithm:    tsAlgID{Algorithm: oidSHA256Verifier},
		SignedAttrs:        asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: other},
		SignatureAlgorithm: tsAlgID{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		Signature:          []byte("x"),
	})
	if _, err := tsVerifyCMS(tsSignedData{EncapContentInfo: tsEncap{EContent: eContent}, SignerInfos: asn1.RawValue{Bytes: missingMD}}, [][]byte{der}); err == nil {
		t.Fatal("signedAttrs without message-digest verified")
	}

	extra, _, _, _ := testTSA(t)
	tstDER := tsStructureTSTInfo(t, oidSHA256Verifier, digest, at)
	hashedLeaf := sha256.Sum256(tstDER)
	leafSig, err := ecdsa.SignASN1(rand.Reader, key, hashedLeaf[:])
	if err != nil {
		t.Fatal(err)
	}
	leafSI := mustASN1(t, tsSignerInfo{
		Version: 1, SID: asn1.RawValue{FullBytes: sid},
		DigestAlgorithm:    tsAlgID{Algorithm: oidSHA256Verifier},
		SignatureAlgorithm: tsAlgID{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		Signature:          leafSig,
	})
	twoTok := tsStructureResponse(t, tsStructureContentInfo(t, oidSignedDataVerifier, mustASN1(t, tsSignedData{
		Version: 3, DigestAlgorithms: asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: mustASN1(t, tsAlgID{Algorithm: oidSHA256Verifier})},
		EncapContentInfo: tsEncap{EContentType: oidTSTInfoVerifier, EContent: tstDER},
		Certificates:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: append(append([]byte(nil), der...), extra...)},
		SignerInfos:      asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: leafSI},
	})), pkiGranted)
	if err := verifyTimestampWithTrust(TimestampView{Digest: hex.EncodeToString(digest), Token: twoTok, Time: at}, pool, time.Time{}); err != nil {
		t.Fatalf("two-cert token = %v", err)
	}

	tok := signedTSToken(t, digest, cert, key)
	if err := verifyTimestampWithTrust(TimestampView{Digest: hex.EncodeToString(digest), Token: tok, Time: testTSGenTime}, pool, time.Time{}); err != nil {
		t.Fatalf("zero-now trust = %v", err)
	}
}

func mustASN1(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func tsStructureTSTInfo(t *testing.T, alg asn1.ObjectIdentifier, digest []byte, at time.Time) []byte {
	t.Helper()
	return mustASN1(t, tsInfo{
		Version: 1, Policy: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59999, 1, 1},
		MessageImprint: tsImprint{HashAlgorithm: tsAlgID{Algorithm: alg}, HashedMessage: digest},
		SerialNumber:   big.NewInt(1), GenTime: at,
	})
}

func tsStructureSignedData(t *testing.T, eType asn1.ObjectIdentifier, eContent []byte) []byte {
	t.Helper()
	alg := mustASN1(t, tsAlgID{Algorithm: oidSHA256Verifier})
	return mustASN1(t, tsSignedData{
		Version: 3, DigestAlgorithms: asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: alg},
		EncapContentInfo: tsEncap{EContentType: eType, EContent: eContent},
		SignerInfos:      asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: nil},
	})
}

func tsStructureContentInfo(t *testing.T, ct asn1.ObjectIdentifier, inner []byte) []byte {
	t.Helper()
	return mustASN1(t, tsContentInfo{ContentType: ct, Content: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: inner}})
}

func tsStructureResponse(t *testing.T, token []byte, status int) []byte {
	t.Helper()
	resp := tsResp{Status: tsPKIStatus{Status: status}}
	if token != nil {
		resp.TimeStampToken = asn1.RawValue{FullBytes: token}
	}
	return mustASN1(t, resp)
}

func tsStructureResponseStatus(t *testing.T, status int) []byte {
	t.Helper()
	return mustASN1(t, tsResp{Status: tsPKIStatus{Status: status}})
}

func TestMarshalResultFallsBackWhenEncoderFails(t *testing.T) {
	orig := resultMarshalIndent
	t.Cleanup(func() { resultMarshalIndent = orig })
	resultMarshalIndent = func(any, string, string) ([]byte, error) {
		return nil, errors.New("marshal refused")
	}
	raw, err := MarshalResult(&Result{OK: true})
	if err == nil {
		t.Fatal("expected marshal fallback error")
	}
	if !bytes.Contains(raw, []byte(`"ok": false`)) && !bytes.Contains(raw, []byte(`"ok":false`)) {
		t.Fatalf("fallback document = %s", raw)
	}
	if !bytes.Contains(raw, []byte("result encoding failed")) {
		t.Fatalf("fallback does not name the encoding failure: %s", raw)
	}
}

func TestVerifyExportReaderResultRecordsLoadFailures(t *testing.T) {
	res := VerifyExportReaderResult(strings.NewReader("not-json\n"), nil, VerifyOptions{})
	if res.OK || len(res.Errors) == 0 {
		t.Fatalf("load failure = %+v", res)
	}
}
