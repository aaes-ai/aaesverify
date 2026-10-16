package hash

import (
	"bytes"
	"crypto/fips140"
	"crypto/sha1" //nolint:gosec // RFC 2634 ESSCertID names the signer by SHA-1; the CMS signature, not this hash, authenticates.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// The RFC 3161 timestamp-token signed-attribute profile, shared by every AAES
// timestamp verifier (internal/witness, internal/audit, internal/verifier and
// the open aaesverify tree, which receives this file through sync.sh).
//
// A token's SignerInfo must carry signedAttrs (RFC 5652 §5.3) with:
//   - contentType equal to id-ct-TSTInfo (RFC 3161 §2.4.2);
//   - messageDigest equal to SHA-256 of the encapsulated TSTInfo;
//   - signingCertificate (ESSCertID, RFC 2634 §5.4, SHA-1) and/or
//     signingCertificateV2 (ESSCertIDv2, RFC 5035/RFC 5816, SHA-256 by
//     default) whose first certHash names the certificate that verified the
//     signature, and whose issuerSerial, when present, names its issuer and
//     serial number. Every such attribute present must bind; at least one must.
//
// A SignerInfo without signedAttrs (a signature directly over the TSTInfo) is
// refused: it binds neither the content type nor the signing certificate.

// ErrTimestampAttrsMalformed reports signed attributes that do not decode.
var ErrTimestampAttrsMalformed = errors.New("timestamp signed attributes are malformed")

// ErrTimestampAttrsBinding reports signed attributes that decode but do not
// bind the token's content type, content, or signing certificate.
var ErrTimestampAttrsBinding = errors.New("timestamp signed attributes do not bind the token")

var (
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningCert   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidAttrSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidContentTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidDigestSHA256      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidDigestSHA384      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidDigestSHA512      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

type tsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type tsAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type essCertID struct {
	CertHash     []byte
	IssuerSerial asn1.RawValue `asn1:"optional"`
}

type essCertIDv2 struct {
	HashAlgorithm tsAlgorithm `asn1:"optional"`
	CertHash      []byte
	IssuerSerial  asn1.RawValue `asn1:"optional"`
}

type signingCertificate struct {
	Certs    []essCertID
	Policies asn1.RawValue `asn1:"optional"`
}

type signingCertificateV2 struct {
	Certs    []essCertIDv2
	Policies asn1.RawValue `asn1:"optional"`
}

type issuerSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

func attrsMalformed(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrTimestampAttrsMalformed}, args...)...)
}

func attrsUnbound(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrTimestampAttrsBinding}, args...)...)
}

// VerifyTimestampSignedAttrs checks the content octets of a SignerInfo's
// [0] IMPLICIT signedAttrs against the encapsulated TSTInfo and the
// certificate that verified the CMS signature. Callers must still verify the
// signature over the DER SET of these attributes under the same certificate.
func VerifyTimestampSignedAttrs(attrs, eContent []byte, signer *x509.Certificate) error {
	if len(attrs) == 0 {
		return attrsUnbound("the SignerInfo carries no signedAttrs; contentType, messageDigest and the signing certificate are unbound")
	}
	if signer == nil || len(signer.Raw) == 0 {
		return attrsUnbound("no signer certificate to bind")
	}
	got, err := parseTimestampAttrs(attrs)
	if err != nil {
		return err
	}
	if err := checkContentTypeAttr(got); err != nil {
		return err
	}
	if err := checkMessageDigestAttr(got, eContent); err != nil {
		return err
	}
	return checkSigningCertAttrs(got, signer)
}

// parseTimestampAttrs returns the single value of each profile attribute.
// A profile attribute that repeats, or carries other than one value, is
// refused; attributes outside the profile are ignored.
func parseTimestampAttrs(attrs []byte) (map[string]asn1.RawValue, error) {
	profile := map[string]bool{
		oidAttrContentType.String():   true,
		oidAttrMessageDigest.String(): true,
		oidAttrSigningCert.String():   true,
		oidAttrSigningCertV2.String(): true,
	}
	out := make(map[string]asn1.RawValue, len(profile))
	for rest := attrs; len(rest) > 0; {
		var attr tsAttribute
		next, err := asn1.Unmarshal(rest, &attr)
		if err != nil {
			return nil, attrsMalformed("signedAttrs do not parse: %v", err)
		}
		rest = next
		key := attr.Type.String()
		if !profile[key] {
			continue
		}
		if _, dup := out[key]; dup {
			return nil, attrsUnbound("signed attribute %s appears more than once", key)
		}
		if len(attr.Values) != 1 {
			return nil, attrsUnbound("signed attribute %s carries %d values, not one", key, len(attr.Values))
		}
		out[key] = attr.Values[0]
	}
	return out, nil
}

func checkContentTypeAttr(got map[string]asn1.RawValue) error {
	v, ok := got[oidAttrContentType.String()]
	if !ok {
		return attrsUnbound("signedAttrs carry no contentType attribute")
	}
	var ct asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(v.FullBytes, &ct); err != nil || len(rest) != 0 {
		return attrsMalformed("the contentType signed attribute is not an OBJECT IDENTIFIER")
	}
	if !ct.Equal(oidContentTSTInfo) {
		return attrsUnbound("the contentType signed attribute is %v, not id-ct-TSTInfo", ct)
	}
	return nil
}

func checkMessageDigestAttr(got map[string]asn1.RawValue, eContent []byte) error {
	v, ok := got[oidAttrMessageDigest.String()]
	if !ok {
		return attrsUnbound("signedAttrs carry no message-digest attribute")
	}
	var md []byte
	if rest, err := asn1.Unmarshal(v.FullBytes, &md); err != nil || len(rest) != 0 {
		return attrsMalformed("the message-digest signed attribute is not an OCTET STRING")
	}
	want := sha256.Sum256(eContent)
	if !bytes.Equal(md, want[:]) {
		return attrsUnbound("the message-digest signed attribute does not match the encapsulated TSTInfo")
	}
	return nil
}

func checkSigningCertAttrs(got map[string]asn1.RawValue, signer *x509.Certificate) error {
	v1, has1 := got[oidAttrSigningCert.String()]
	v2, has2 := got[oidAttrSigningCertV2.String()]
	if !has1 && !has2 {
		return attrsUnbound("signedAttrs carry no signingCertificate (ESSCertID) or signingCertificateV2 (ESSCertIDv2) attribute")
	}
	if has1 {
		if err := checkESSCertID(v1, signer); err != nil {
			return err
		}
	}
	if has2 {
		return checkESSCertIDv2(v2, signer)
	}
	return nil
}

func checkESSCertID(v asn1.RawValue, signer *x509.Certificate) error {
	var sc signingCertificate
	if rest, err := asn1.Unmarshal(v.FullBytes, &sc); err != nil || len(rest) != 0 {
		return attrsMalformed("the signingCertificate attribute does not parse: %v", err)
	}
	if len(sc.Certs) == 0 {
		return attrsUnbound("the signingCertificate attribute names no certificate")
	}
	if fips140.Enabled() {
		return attrsUnbound("ESSCertID requires SHA-1, which is refused in FIPS mode; use signingCertificateV2 with SHA-256 or stronger")
	}
	sum := sha1.Sum(signer.Raw) //nolint:gosec // ESSCertID is defined over SHA-1.
	return checkCertBinding("ESSCertID", sc.Certs[0].CertHash, sum[:], sc.Certs[0].IssuerSerial, signer)
}

func checkESSCertIDv2(v asn1.RawValue, signer *x509.Certificate) error {
	var sc signingCertificateV2
	if rest, err := asn1.Unmarshal(v.FullBytes, &sc); err != nil || len(rest) != 0 {
		return attrsMalformed("the signingCertificateV2 attribute does not parse: %v", err)
	}
	if len(sc.Certs) == 0 {
		return attrsUnbound("the signingCertificateV2 attribute names no certificate")
	}
	first := sc.Certs[0]
	want, err := certDigest(first.HashAlgorithm.Algorithm, signer.Raw)
	if err != nil {
		return err
	}
	return checkCertBinding("ESSCertIDv2", first.CertHash, want, first.IssuerSerial, signer)
}

// certDigest hashes the certificate under the ESSCertIDv2 hashAlgorithm; an
// absent algorithm is the DEFAULT id-sha256.
func certDigest(alg asn1.ObjectIdentifier, raw []byte) ([]byte, error) {
	switch {
	case len(alg) == 0 || alg.Equal(oidDigestSHA256):
		s := sha256.Sum256(raw)
		return s[:], nil
	case alg.Equal(oidDigestSHA384):
		s := sha512.Sum384(raw)
		return s[:], nil
	case alg.Equal(oidDigestSHA512):
		s := sha512.Sum512(raw)
		return s[:], nil
	default:
		return nil, attrsUnbound("ESSCertIDv2 hash algorithm %v is not SHA-256, SHA-384 or SHA-512", alg)
	}
}

func checkCertBinding(kind string, got, want []byte, is asn1.RawValue, signer *x509.Certificate) error {
	if !bytes.Equal(got, want) {
		return attrsUnbound("the %s certHash does not match the certificate that verified the signature", kind)
	}
	if len(is.FullBytes) == 0 {
		return nil
	}
	var ser issuerSerial
	if rest, err := asn1.Unmarshal(is.FullBytes, &ser); err != nil || len(rest) != 0 || ser.SerialNumber == nil {
		return attrsMalformed("the %s issuerSerial does not parse", kind)
	}
	if signer.SerialNumber == nil || ser.SerialNumber.Cmp(signer.SerialNumber) != 0 {
		return attrsUnbound("the %s issuerSerial serial number does not match the signing certificate", kind)
	}
	if !generalNamesHoldDirectoryName(ser.Issuer.Bytes, signer.RawIssuer) {
		return attrsUnbound("the %s issuerSerial issuer does not match the signing certificate", kind)
	}
	return nil
}

// generalNamesHoldDirectoryName reports whether a GeneralNames SEQUENCE body
// carries a directoryName ([4] EXPLICIT Name) equal to rawName.
func generalNamesHoldDirectoryName(names, rawName []byte) bool {
	for rest := names; len(rest) > 0; {
		var gn asn1.RawValue
		next, err := asn1.Unmarshal(rest, &gn)
		if err != nil {
			return false
		}
		rest = next
		if gn.Class == asn1.ClassContextSpecific && gn.Tag == 4 && gn.IsCompound && bytes.Equal(gn.Bytes, rawName) {
			return true
		}
	}
	return false
}
