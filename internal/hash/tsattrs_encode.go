package hash

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"sort"
)

// DER content octets of the object identifiers TimestampSignedAttrs emits;
// tsattrs_test.go checks each against encoding/asn1.
var (
	derOIDContentType   = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03}
	derOIDMessageDigest = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04}
	derOIDSigningCertV2 = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f}
	derOIDTSTInfo       = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04}
)

const (
	derTagOctetString = 0x04
	derTagOID         = 0x06
	derTagSequence    = 0x30
	derTagSet         = 0x31
)

// derTLV encodes one DER tag-length-value with a definite length.
func derTLV(tag byte, parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	n := len(body)
	if n < 0x80 {
		return append([]byte{tag, byte(n)}, body...)
	}
	var length []byte
	for ; n > 0; n >>= 8 {
		length = append([]byte{byte(n)}, length...)
	}
	out := append([]byte{tag, 0x80 | byte(len(length))}, length...)
	return append(out, body...)
}

// TimestampSignedAttrs encodes the content octets of a conforming signedAttrs
// SET for a token whose encapsulated TSTInfo is eContent and whose signer is
// signer: contentType (id-ct-TSTInfo), messageDigest (SHA-256) and
// signingCertificateV2 with one SHA-256 ESSCertIDv2 (hashAlgorithm left at
// its DEFAULT, issuerSerial omitted), in DER SET OF order. A TSA signs the
// DER SET of these octets; test authorities use it to mint conforming tokens.
func TimestampSignedAttrs(eContent []byte, signer *x509.Certificate) ([]byte, error) {
	if signer == nil || len(signer.Raw) == 0 {
		return nil, attrsUnbound("no signer certificate to bind")
	}
	md := sha256.Sum256(eContent)
	certHash := sha256.Sum256(signer.Raw)
	attr := func(oid []byte, value []byte) []byte {
		return derTLV(derTagSequence, derTLV(derTagOID, oid), derTLV(derTagSet, value))
	}
	essCertIDv2 := derTLV(derTagSequence, derTLV(derTagOctetString, certHash[:]))
	encoded := [][]byte{
		attr(derOIDContentType, derTLV(derTagOID, derOIDTSTInfo)),
		attr(derOIDMessageDigest, derTLV(derTagOctetString, md[:])),
		attr(derOIDSigningCertV2, derTLV(derTagSequence, derTLV(derTagSequence, essCertIDv2))),
	}
	sort.Slice(encoded, func(i, j int) bool { return bytes.Compare(encoded[i], encoded[j]) < 0 })
	return bytes.Join(encoded, nil), nil
}
