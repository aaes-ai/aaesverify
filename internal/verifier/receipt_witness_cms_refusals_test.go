package verifier

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestBindReceiptEntryRefusesHashLeafAndCanonicaliseFailures(t *testing.T) {
	entries, _, _, _ := buildLog(t, 2)
	e := entries[0]
	if err := bindReceiptEntry(ReceiptView{
		TenantID: e.TenantID, IntentID: e.IntentID, GrantID: e.GrantID,
		RecordHash: "other-hash", Entry: &e, Leaf: e.Leaf,
	}); err == nil || !strings.Contains(err.Error(), "record hash") {
		t.Fatalf("record hash mismatch = %v", err)
	}
	nan := e
	nan.AmountMinor = 1
	nan.AmountCurrency = ""
	if err := bindReceiptEntry(ReceiptView{
		TenantID: nan.TenantID, IntentID: nan.IntentID, GrantID: nan.GrantID,
		RecordHash: nan.RecordHash, Entry: &nan, Leaf: e.Leaf,
	}); err == nil {
		t.Fatal("invalid amount entry canonicalised")
	}
	shifted := e
	shifted.AmountMinor = e.AmountMinor + 1
	if err := bindReceiptEntry(ReceiptView{
		TenantID: shifted.TenantID, IntentID: shifted.IntentID, GrantID: shifted.GrantID,
		RecordHash: shifted.RecordHash, Entry: &shifted, Leaf: e.Leaf,
	}); err == nil || !strings.Contains(err.Error(), "leaf") {
		t.Fatalf("leaf mismatch = %v", err)
	}
}

func TestWitnessIdentitiesRefuseARepeatedWitnessID(t *testing.T) {
	w := &witnessIdentities{}
	if !w.add("w1", []byte{1, 2, 3}) {
		t.Fatal("first identity was refused")
	}
	if w.add("w1", []byte{4, 5, 6}) {
		t.Fatal("the same witness id was counted twice under a new key")
	}
}

func TestPromoteIndependenceLimitsKeepsUnrelatedWarnings(t *testing.T) {
	res := &Result{Warnings: []string{
		"independent witnesses share a public key",
		"the chain is complete",
	}}
	promoteIndependenceLimits(res)
	if len(res.Warnings) != 1 || res.Warnings[0] != "the chain is complete" {
		t.Fatalf("kept warnings = %v", res.Warnings)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "independent") {
		t.Fatalf("promoted errors = %v", res.Errors)
	}
}

func TestVerifyTimestampWithTrustRefusesAMalformedCertificateBag(t *testing.T) {
	digest := bytesRepeat32(7)
	at := testTSGenTime
	garbageBag := tsStructureResponse(t, tsStructureContentInfo(t, oidSignedDataVerifier, mustASN1(t, tsSignedData{
		Version:          3,
		DigestAlgorithms: asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: mustASN1(t, tsAlgID{Algorithm: oidSHA256Verifier})},
		EncapContentInfo: tsEncap{EContentType: oidTSTInfoVerifier, EContent: tsStructureTSTInfo(t, oidSHA256Verifier, digest, at)},
		Certificates:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{0x01, 0x02}},
		SignerInfos:      asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: nil},
	})), pkiGranted)
	if err := verifyTimestampWithTrust(TimestampView{
		Digest: hex.EncodeToString(digest), Token: garbageBag, Time: at,
	}, x509.NewCertPool(), time.Time{}); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("garbage certificate bag = %v", err)
	}

	der, _, pool, _ := testTSA(t)
	noSI := tsStructureResponse(t, tsStructureContentInfo(t, oidSignedDataVerifier, mustASN1(t, tsSignedData{
		Version:          3,
		DigestAlgorithms: asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: mustASN1(t, tsAlgID{Algorithm: oidSHA256Verifier})},
		EncapContentInfo: tsEncap{EContentType: oidTSTInfoVerifier, EContent: tsStructureTSTInfo(t, oidSHA256Verifier, digest, at)},
		Certificates:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: der},
		SignerInfos:      asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: nil},
	})), pkiGranted)
	if err := verifyTimestampWithTrust(TimestampView{
		Digest: hex.EncodeToString(digest), Token: noSI, Time: at,
	}, pool, time.Time{}); err == nil {
		t.Fatal("a certificate without SignerInfos was trusted")
	}
}

func TestTsVerifyCMSRefusesGarbageSignerInfos(t *testing.T) {
	if _, err := tsVerifyCMS(tsSignedData{
		SignerInfos:      asn1.RawValue{Bytes: []byte{0x01}},
		EncapContentInfo: tsEncap{EContent: []byte("x")},
	}, nil); err == nil {
		t.Fatal("garbage SignerInfos verified")
	}
}

func bytesRepeat32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
