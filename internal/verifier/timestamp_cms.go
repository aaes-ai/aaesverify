package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

func tsCertificates(field asn1.RawValue) ([][]byte, error) {
	if len(field.Bytes) == 0 {
		return nil, nil
	}
	out := make([][]byte, 0, 2)
	rest := field.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		next, err := asn1.Unmarshal(rest, &v)
		if err != nil {
			return nil, fmt.Errorf("the token certificate field is not a sequence of certificates: %v", err)
		}
		if len(v.FullBytes) == 0 {
			return nil, fmt.Errorf("the token certificate field is present but empty")
		}
		out = append(out, append([]byte(nil), v.FullBytes...))
		rest = next
	}
	return out, nil
}

func tsVerifyCMS(sd tsSignedData, certDERs [][]byte) (*x509.Certificate, error) {
	infos, err := tsParseSignerInfos(sd.SignerInfos)
	if err != nil {
		return nil, err
	}
	certs := make([]*x509.Certificate, 0, len(certDERs))
	for i, der := range certDERs {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("token certificate %d does not parse: %v", i, err)
		}
		certs = append(certs, cert)
	}
	eContent := sd.EncapContentInfo.EContent
	var last error
	for _, si := range infos {
		cert := tsMatchSigner(si, certs)
		if cert == nil {
			last = fmt.Errorf("a SignerInfo names no certificate carried in the token")
			continue
		}
		if err := tsVerifySigner(si, cert, eContent); err != nil {
			last = err
			continue
		}
		return cert, nil
	}
	if last != nil {
		return nil, last
	}
	return nil, fmt.Errorf("no CMS SignerInfo verified under a certificate in the token")
}

func tsParseSignerInfos(raw asn1.RawValue) ([]tsSignerInfo, error) {
	inner := raw.Bytes
	if len(inner) == 0 {
		return nil, fmt.Errorf("the token carries no SignerInfos; an empty SET is not a signer")
	}
	var out []tsSignerInfo
	rest := inner
	for len(rest) > 0 {
		var si tsSignerInfo
		next, err := asn1.Unmarshal(rest, &si)
		if err != nil {
			return nil, fmt.Errorf("SignerInfo does not parse: %v", err)
		}
		if len(si.Signature) == 0 {
			return nil, fmt.Errorf("a SignerInfo carries no signature")
		}
		out = append(out, si)
		rest = next
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the token carries no SignerInfos; an empty SET is not a signer")
	}
	return out, nil
}

func tsMatchSigner(si tsSignerInfo, certs []*x509.Certificate) *x509.Certificate {
	var ias struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}
	if rest, err := asn1.Unmarshal(si.SID.FullBytes, &ias); err == nil && len(rest) == 0 {
		for _, c := range certs {
			if c.SerialNumber != nil && ias.SerialNumber != nil &&
				c.SerialNumber.Cmp(ias.SerialNumber) == 0 &&
				bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) {
				return c
			}
		}
	}
	if si.SID.Class == 2 && si.SID.Tag == 0 && len(si.SID.Bytes) > 0 {
		for _, c := range certs {
			if len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, si.SID.Bytes) {
				return c
			}
		}
	}
	return nil
}

func tsVerifySigner(si tsSignerInfo, cert *x509.Certificate, eContent []byte) error {
	algo, err := tsSigAlg(si.DigestAlgorithm.Algorithm, cert.PublicKey)
	if err != nil {
		return err
	}
	signed := eContent
	if len(si.SignedAttrs.Bytes) > 0 || len(si.SignedAttrs.FullBytes) > 0 {
		if err := tsCheckMessageDigest(si.SignedAttrs.Bytes, eContent); err != nil {
			return err
		}
		set, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: si.SignedAttrs.Bytes})
		if err != nil {
			return fmt.Errorf("signedAttrs could not be re-encoded: %v", err)
		}
		signed = set
	}
	if err := cert.CheckSignature(algo, signed, si.Signature); err != nil {
		return fmt.Errorf("the CMS SignerInfo signature does not verify: %v", err)
	}
	return nil
}

func tsCheckMessageDigest(attrBytes, eContent []byte) error {
	want := sha256.Sum256(eContent)
	rest := attrBytes
	found := false
	for len(rest) > 0 {
		var attr struct {
			Type   asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}
		next, err := asn1.Unmarshal(rest, &attr)
		if err != nil {
			return fmt.Errorf("signedAttrs do not parse: %v", err)
		}
		rest = next
		if !attr.Type.Equal(oidMessageDigestV) {
			continue
		}
		if len(attr.Values) == 0 {
			return fmt.Errorf("the message-digest signed attribute has no value")
		}
		var got []byte
		if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &got); err != nil {
			return fmt.Errorf("the message-digest signed attribute is not an OCTET STRING: %v", err)
		}
		if !bytes.Equal(got, want[:]) {
			return fmt.Errorf("the message-digest signed attribute does not match the encapsulated content")
		}
		found = true
	}
	if !found {
		return fmt.Errorf("signedAttrs are present but carry no message-digest attribute")
	}
	return nil
}

func tsSigAlg(digest asn1.ObjectIdentifier, pub any) (x509.SignatureAlgorithm, error) {
	if !digest.Equal(oidSHA256Verifier) {
		return 0, fmt.Errorf("CMS digest algorithm is %v, not SHA-256", digest)
	}
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return x509.ECDSAWithSHA256, nil
	case *rsa.PublicKey:
		return x509.SHA256WithRSA, nil
	case ed25519.PublicKey:
		return x509.PureEd25519, nil
	default:
		return 0, fmt.Errorf("unsupported CMS public key type %T", pub)
	}
}
