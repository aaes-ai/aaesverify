package hash

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func tsAttrsTestCert(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "tsattrs-tsa"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<32, 0),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func tsAttrsDER(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func tsAttr(t *testing.T, oid asn1.ObjectIdentifier, values ...[]byte) []byte {
	t.Helper()
	raws := make([]asn1.RawValue, 0, len(values))
	for _, v := range values {
		raws = append(raws, asn1.RawValue{FullBytes: v})
	}
	return tsAttrsDER(t, tsAttribute{Type: oid, Values: raws})
}

func tsIssuerSerial(t *testing.T, rawIssuer []byte, serial *big.Int) asn1.RawValue {
	t.Helper()
	names := tsAttrsDER(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: rawIssuer})
	return asn1.RawValue{FullBytes: tsAttrsDER(t, issuerSerial{
		Issuer:       asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: names},
		SerialNumber: serial,
	})}
}

type tsAttrParts struct {
	contentType []byte
	digest      []byte
	v1          []byte
	v2          []byte
	extra       [][]byte
}

func (p tsAttrParts) join() []byte {
	var out []byte
	for _, b := range [][]byte{p.contentType, p.digest, p.v1, p.v2} {
		out = append(out, b...)
	}
	for _, b := range p.extra {
		out = append(out, b...)
	}
	return out
}

func tsGoodParts(t *testing.T, eContent []byte, cert *x509.Certificate) tsAttrParts {
	t.Helper()
	md := sha256.Sum256(eContent)
	v2Hash := sha256.Sum256(cert.Raw)
	return tsAttrParts{
		contentType: tsAttr(t, oidAttrContentType, tsAttrsDER(t, oidContentTSTInfo)),
		digest:      tsAttr(t, oidAttrMessageDigest, tsAttrsDER(t, md[:])),
		v2: tsAttr(t, oidAttrSigningCertV2, tsAttrsDER(t, signingCertificateV2{Certs: []essCertIDv2{{
			CertHash: v2Hash[:], IssuerSerial: tsIssuerSerial(t, cert.RawIssuer, cert.SerialNumber),
		}}})),
	}
}

func TestTimestampSignedAttrsBuilderVerifies(t *testing.T) {
	cert := tsAttrsTestCert(t, 7)
	eContent := []byte("tstinfo")
	attrs, err := TimestampSignedAttrs(eContent, cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTimestampSignedAttrs(attrs, eContent, cert); err != nil {
		t.Fatalf("builder output refused: %v", err)
	}
	if err := VerifyTimestampSignedAttrs(attrs, []byte("other"), cert); !errors.Is(err, ErrTimestampAttrsBinding) {
		t.Fatalf("other content = %v", err)
	}
	if err := VerifyTimestampSignedAttrs(attrs, eContent, tsAttrsTestCert(t, 7)); !errors.Is(err, ErrTimestampAttrsBinding) {
		t.Fatalf("other certificate = %v", err)
	}
	if _, err := TimestampSignedAttrs(eContent, nil); !errors.Is(err, ErrTimestampAttrsBinding) {
		t.Fatalf("nil signer builder = %v", err)
	}
}

func TestTimestampSignedAttrsAcceptsConformingVariants(t *testing.T) {
	cert := tsAttrsTestCert(t, 9)
	eContent := []byte("tstinfo")
	var sha1Sum [sha1.Size]byte
	if !fips140.Enabled() {
		sha1Sum = sha1.Sum(cert.Raw)
	}
	sha384Sum := sha512.Sum384(cert.Raw)
	sha512Sum := sha512.Sum512(cert.Raw)
	sha256Sum := sha256.Sum256(cert.Raw)
	v1 := tsAttr(t, oidAttrSigningCert, tsAttrsDER(t, signingCertificate{Certs: []essCertID{{CertHash: sha1Sum[:]}}}))
	v1Serial := tsAttr(t, oidAttrSigningCert, tsAttrsDER(t, signingCertificate{Certs: []essCertID{{
		CertHash: sha1Sum[:], IssuerSerial: tsIssuerSerial(t, cert.RawIssuer, cert.SerialNumber),
	}}}))
	v2Alg := func(alg asn1.ObjectIdentifier, sum []byte) []byte {
		return tsAttr(t, oidAttrSigningCertV2, tsAttrsDER(t, signingCertificateV2{Certs: []essCertIDv2{{
			HashAlgorithm: tsAlgorithm{Algorithm: alg}, CertHash: sum,
		}}}))
	}
	signingTime := tsAttr(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}, tsAttrsDER(t, time.Unix(0, 0).UTC()))
	cases := map[string]func(p *tsAttrParts){
		"v2 with issuerSerial":  func(*tsAttrParts) {},
		"v1 only":               func(p *tsAttrParts) { p.v2, p.v1 = nil, v1 },
		"v1 with issuerSerial":  func(p *tsAttrParts) { p.v2, p.v1 = nil, v1Serial },
		"v1 and v2":             func(p *tsAttrParts) { p.v1 = v1 },
		"v2 explicit SHA-256":   func(p *tsAttrParts) { p.v2 = v2Alg(oidDigestSHA256, sha256Sum[:]) },
		"v2 SHA-384":            func(p *tsAttrParts) { p.v2 = v2Alg(oidDigestSHA384, sha384Sum[:]) },
		"v2 SHA-512":            func(p *tsAttrParts) { p.v2 = v2Alg(oidDigestSHA512, sha512Sum[:]) },
		"unrelated signingTime": func(p *tsAttrParts) { p.extra = [][]byte{signingTime} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := tsGoodParts(t, eContent, cert)
			mutate(&p)
			err := VerifyTimestampSignedAttrs(p.join(), eContent, cert)
			if fips140.Enabled() && p.v1 != nil {
				if !errors.Is(err, ErrTimestampAttrsBinding) || !strings.Contains(err.Error(), "refused in FIPS mode") {
					t.Fatalf("legacy SHA-1 timestamp must refuse without panic in FIPS mode: %v", err)
				}
			} else if err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}

func TestTimestampSignedAttrsRefusals(t *testing.T) {
	cert := tsAttrsTestCert(t, 11)
	eContent := []byte("tstinfo")
	other := tsAttrsTestCert(t, 12)
	otherV2 := sha256.Sum256(other.Raw)
	sha256Sum := sha256.Sum256(cert.Raw)
	var sha1Other [sha1.Size]byte
	if !fips140.Enabled() {
		sha1Other = sha1.Sum(other.Raw)
	}
	wrongMD := sha256.Sum256([]byte("other"))
	v2With := func(sc signingCertificateV2) []byte {
		return tsAttr(t, oidAttrSigningCertV2, tsAttrsDER(t, sc))
	}
	bad := ErrTimestampAttrsBinding
	malformed := ErrTimestampAttrsMalformed
	cases := []struct {
		name   string
		mutate func(p *tsAttrParts)
		want   error
	}{
		{"missing contentType", func(p *tsAttrParts) { p.contentType = nil }, bad},
		{"wrong contentType", func(p *tsAttrParts) {
			p.contentType = tsAttr(t, oidAttrContentType, tsAttrsDER(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}))
		}, bad},
		{"contentType not an OID", func(p *tsAttrParts) { p.contentType = tsAttr(t, oidAttrContentType, tsAttrsDER(t, 5)) }, malformed},
		{"two contentType values", func(p *tsAttrParts) {
			p.contentType = tsAttr(t, oidAttrContentType, tsAttrsDER(t, oidContentTSTInfo), tsAttrsDER(t, oidContentTSTInfo))
		}, bad},
		{"repeated contentType", func(p *tsAttrParts) { p.extra = [][]byte{p.contentType} }, bad},
		{"missing messageDigest", func(p *tsAttrParts) { p.digest = nil }, bad},
		{"messageDigest mismatch", func(p *tsAttrParts) { p.digest = tsAttr(t, oidAttrMessageDigest, tsAttrsDER(t, wrongMD[:])) }, bad},
		{"messageDigest not an OCTET STRING", func(p *tsAttrParts) { p.digest = tsAttr(t, oidAttrMessageDigest, tsAttrsDER(t, 1)) }, malformed},
		{"no ESSCertID or ESSCertIDv2", func(p *tsAttrParts) { p.v2 = nil }, bad},
		{"ESSCertIDv2 names another certificate", func(p *tsAttrParts) {
			p.v2 = v2With(signingCertificateV2{Certs: []essCertIDv2{{CertHash: otherV2[:]}}})
		}, bad},
		{"ESSCertIDv2 first entry is not the signer", func(p *tsAttrParts) {
			p.v2 = v2With(signingCertificateV2{Certs: []essCertIDv2{{CertHash: otherV2[:]}, {CertHash: sha256Sum[:]}}})
		}, bad},
		{"ESSCertIDv2 empty", func(p *tsAttrParts) { p.v2 = v2With(signingCertificateV2{Certs: []essCertIDv2{}}) }, bad},
		{"ESSCertIDv2 unsupported hash", func(p *tsAttrParts) {
			p.v2 = v2With(signingCertificateV2{Certs: []essCertIDv2{{HashAlgorithm: tsAlgorithm{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}}, CertHash: sha256Sum[:]}}})
		}, bad},
		{"ESSCertIDv2 does not parse", func(p *tsAttrParts) { p.v2 = tsAttr(t, oidAttrSigningCertV2, tsAttrsDER(t, 3)) }, malformed},
		{"ESSCertIDv2 wrong serial", func(p *tsAttrParts) {
			p.v2 = v2With(signingCertificateV2{Certs: []essCertIDv2{{CertHash: sha256Sum[:], IssuerSerial: tsIssuerSerial(t, cert.RawIssuer, big.NewInt(99))}}})
		}, bad},
		{"ESSCertIDv2 wrong issuer", func(p *tsAttrParts) {
			p.v2 = v2With(signingCertificateV2{Certs: []essCertIDv2{{CertHash: sha256Sum[:], IssuerSerial: tsIssuerSerial(t, tsAttrsDER(t, pkix.Name{CommonName: "x"}.ToRDNSequence()), cert.SerialNumber)}}})
		}, bad},
		{"ESSCertIDv2 issuerSerial does not parse", func(p *tsAttrParts) {
			p.v2 = v2With(signingCertificateV2{Certs: []essCertIDv2{{CertHash: sha256Sum[:], IssuerSerial: asn1.RawValue{FullBytes: tsAttrsDER(t, 4)}}}})
		}, malformed},
		{"ESSCertID names another certificate", func(p *tsAttrParts) {
			p.v1 = tsAttr(t, oidAttrSigningCert, tsAttrsDER(t, signingCertificate{Certs: []essCertID{{CertHash: sha1Other[:]}}}))
		}, bad},
		{"ESSCertID empty", func(p *tsAttrParts) {
			p.v1 = tsAttr(t, oidAttrSigningCert, tsAttrsDER(t, signingCertificate{Certs: []essCertID{}}))
		}, bad},
		{"ESSCertID does not parse", func(p *tsAttrParts) { p.v1 = tsAttr(t, oidAttrSigningCert, tsAttrsDER(t, 3)) }, malformed},
		{"garbage attribute", func(p *tsAttrParts) { p.extra = [][]byte{{0x01}} }, malformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tsGoodParts(t, eContent, cert)
			tc.mutate(&p)
			if err := VerifyTimestampSignedAttrs(p.join(), eContent, cert); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	good := tsGoodParts(t, eContent, cert).join()
	if err := VerifyTimestampSignedAttrs(nil, eContent, cert); !errors.Is(err, bad) {
		t.Fatalf("absent signedAttrs = %v", err)
	}
	if err := VerifyTimestampSignedAttrs(good, eContent, nil); !errors.Is(err, bad) {
		t.Fatalf("nil signer = %v", err)
	}
	noSerial := *cert
	noSerial.SerialNumber = nil
	if err := VerifyTimestampSignedAttrs(good, eContent, &noSerial); !errors.Is(err, bad) {
		t.Fatalf("signer without serial = %v", err)
	}
}

func TestGeneralNamesHoldDirectoryNameRefusesGarbage(t *testing.T) {
	if generalNamesHoldDirectoryName([]byte{0x01}, []byte{0x30, 0x00}) {
		t.Fatal("garbage GeneralNames matched")
	}
	dns := tsAttrsDER(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("tsa.example")})
	if generalNamesHoldDirectoryName(dns, []byte("tsa.example")) {
		t.Fatal("a dNSName matched as a directoryName")
	}
}

func TestTimestampSignedAttrsEncodingMatchesEncodingASN1(t *testing.T) {
	for oid, body := range map[string][]byte{
		oidAttrContentType.String():   derOIDContentType,
		oidAttrMessageDigest.String(): derOIDMessageDigest,
		oidAttrSigningCertV2.String(): derOIDSigningCertV2,
		oidContentTSTInfo.String():    derOIDTSTInfo,
	} {
		var got asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(derTLV(derTagOID, body), &got); err != nil || len(rest) != 0 || got.String() != oid {
			t.Fatalf("DER OID %x decodes to %v (%v), want %s", body, got, err, oid)
		}
	}
	for _, n := range []int{0, 127, 128, 255, 256, 70000} {
		body := make([]byte, n)
		if want := tsAttrsDER(t, body); !bytes.Equal(derTLV(derTagOctetString, body), want) {
			t.Fatalf("derTLV of %d bytes differs from encoding/asn1", n)
		}
	}
	cert := tsAttrsTestCert(t, 13)
	attrs, err := TimestampSignedAttrs([]byte("tstinfo"), cert)
	if err != nil {
		t.Fatal(err)
	}
	var set []tsAttribute
	if rest, err := asn1.UnmarshalWithParams(derTLV(derTagSet, attrs), &set, "set"); err != nil || len(rest) != 0 || len(set) != 3 {
		t.Fatalf("builder output is not a DER SET of three attributes: %d %v", len(set), err)
	}
	if _, err := TimestampSignedAttrs(nil, &x509.Certificate{}); !errors.Is(err, ErrTimestampAttrsBinding) {
		t.Fatalf("certificate without DER = %v", err)
	}
}
