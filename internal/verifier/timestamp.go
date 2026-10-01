package verifier

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
)

// RFC 3161 / CMS object identifiers used by the timestamp independence check.
// Duplicated from internal/witness because this package must not import it.
var (
	oidSHA256Verifier     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSignedDataVerifier = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfoVerifier    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidMessageDigestV     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

const (
	pkiGranted     = 0
	pkiGrantedMods = 1
)

type tsAlgID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type tsImprint struct {
	HashAlgorithm tsAlgID
	HashedMessage []byte
}

type tsPKIStatus struct {
	Status       int
	StatusString asn1.RawValue `asn1:"optional"`
	FailInfo     asn1.RawValue `asn1:"optional"`
}

type tsResp struct {
	Status         tsPKIStatus
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type tsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type tsSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue `asn1:"set"`
	EncapContentInfo tsEncap
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue `asn1:"set"`
}

type tsEncap struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

type tsInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint tsImprint
	SerialNumber   *big.Int
	GenTime        time.Time     `asn1:"generalized"`
	Accuracy       asn1.RawValue `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *big.Int      `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,explicit,tag:0"`
	Extensions     asn1.RawValue `asn1:"optional,tag:1"`
}

type tsSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    tsAlgID
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm tsAlgID
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

// verifyTimestampWithTrust is this package's counterpart of
// witness.HTTPTimestamp.VerifyWithTrust. The verifier cannot import that package;
// the checks are the same: the token binds the claimed digest, a CMS SignerInfo
// signature verifies, and the signer chains to the caller-supplied TSA roots.
func verifyTimestampWithTrust(ts TimestampView, roots *x509.CertPool, now time.Time) error {
	if roots == nil {
		return fmt.Errorf("no TSA trust roots supplied")
	}
	if ts.Noop {
		return fmt.Errorf("timestamp is a noop placeholder")
	}
	if len(ts.Token) == 0 {
		return fmt.Errorf("timestamp carries no RFC 3161 token")
	}
	sd, info, err := parseTimestampCMS(ts.Token)
	if err != nil {
		return err
	}
	if err := verifyTimestampImprint(ts, info); err != nil {
		return err
	}
	ders, err := tsCertificates(sd.Certificates)
	if err != nil {
		return err
	}
	if len(ders) == 0 {
		return fmt.Errorf("the token carries no signer certificate")
	}
	signer, err := tsVerifyCMS(sd, ders)
	if err != nil {
		return err
	}
	return verifyTimestampChain(signer, ders, roots, now, info.GenTime)
}

// verifyTimestampImprint checks that the token binds the claimed digest: the
// imprint algorithm is SHA-256, the imprinted bytes are the digest the export
// records, and the claimed time is the token's own GenTime.
func verifyTimestampImprint(ts TimestampView, info tsInfo) error {
	if !info.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256Verifier) {
		return fmt.Errorf("the token imprints %v, not SHA-256", info.MessageImprint.HashAlgorithm.Algorithm)
	}
	if hex.EncodeToString(info.MessageImprint.HashedMessage) != ts.Digest {
		return fmt.Errorf("the token imprints %s, not %s", hex.EncodeToString(info.MessageImprint.HashedMessage), ts.Digest)
	}
	if ts.Time.IsZero() || info.GenTime.IsZero() || !ts.Time.UTC().Truncate(time.Second).Equal(info.GenTime.UTC().Truncate(time.Second)) {
		return fmt.Errorf("the timestamp time %s is not the token GenTime %s", ts.Time.UTC().Format(time.RFC3339Nano), info.GenTime.UTC().Format(time.RFC3339Nano))
	}
	return nil
}

// verifyTimestampChain checks that the signer the CMS signature verified under
// chains to a caller-supplied TSA root, using the token's other certificates
// as intermediates. A zero now means validate at GenTime (the token's own
// time); when GenTime is also zero the process clock is the last resort.
func verifyTimestampChain(signer *x509.Certificate, ders [][]byte, roots *x509.CertPool, now, genTime time.Time) error {
	intermediates := x509.NewCertPool()
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		if bytes.Equal(cert.Raw, signer.Raw) {
			continue
		}
		intermediates.AddCert(cert)
	}
	at := now
	if at.IsZero() {
		at = genTime
		if at.IsZero() {
			at = time.Now().UTC()
		}
	}
	if _, err := signer.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		return fmt.Errorf("the token signer does not chain to a supplied root: %v", err)
	}
	return nil
}

func parseTimestampCMS(token []byte) (tsSignedData, tsInfo, error) {
	var resp tsResp
	rest, err := asn1.Unmarshal(token, &resp)
	if err != nil {
		return tsSignedData{}, tsInfo{}, fmt.Errorf("response is not DER: %v", err)
	}
	if len(rest) != 0 {
		return tsSignedData{}, tsInfo{}, fmt.Errorf("%d bytes follow the response", len(rest))
	}
	switch resp.Status.Status {
	case pkiGranted, pkiGrantedMods:
	default:
		return tsSignedData{}, tsInfo{}, fmt.Errorf("the authority answered with PKIStatus %d", resp.Status.Status)
	}
	if len(resp.TimeStampToken.FullBytes) == 0 {
		return tsSignedData{}, tsInfo{}, fmt.Errorf("a granted response carries no token")
	}
	var ci tsContentInfo
	rest, err = asn1.Unmarshal(resp.TimeStampToken.FullBytes, &ci)
	if err != nil || len(rest) != 0 {
		return tsSignedData{}, tsInfo{}, fmt.Errorf("the token is not a ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(oidSignedDataVerifier) {
		return tsSignedData{}, tsInfo{}, fmt.Errorf("the token is %v, not signed data", ci.ContentType)
	}
	var sd tsSignedData
	rest, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil || len(rest) != 0 {
		return tsSignedData{}, tsInfo{}, fmt.Errorf("the token is not SignedData: %v", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfoVerifier) {
		return tsSignedData{}, tsInfo{}, fmt.Errorf("the encapsulated content is %v, not a TSTInfo", sd.EncapContentInfo.EContentType)
	}
	if len(sd.EncapContentInfo.EContent) == 0 {
		return tsSignedData{}, tsInfo{}, fmt.Errorf("the encapsulated TSTInfo is absent")
	}
	var info tsInfo
	rest, err = asn1.Unmarshal(sd.EncapContentInfo.EContent, &info)
	if err != nil || len(rest) != 0 {
		return tsSignedData{}, tsInfo{}, fmt.Errorf("the TSTInfo does not parse: %v", err)
	}
	return sd, info, nil
}
