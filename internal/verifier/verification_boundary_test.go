package verifier

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
)

type blankExportReader struct{ chunk []byte }

func (r blankExportReader) Read(p []byte) (int, error) {
	n := copy(p, r.chunk)
	p[n-1] = '\n'
	return n, nil
}

func TestVerifierRefusesOversizedStreamsAndIncompleteJSON(t *testing.T) {
	r := blankExportReader{chunk: bytes.Repeat([]byte(" "), 64<<10)}
	if _, err := LoadExportReader(io.LimitReader(r, MaxExportBytes+1)); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatal("oversized blank export accepted", err)
	}
	if _, err := ParseUsageReport(bytes.Repeat([]byte(" "), MaxUsageReportBytes+1)); !errors.Is(err, ErrUsageReport) {
		t.Fatal("oversized usage report accepted", err)
	}
	if err := rejectDuplicateMembers([]byte(`{"unclosed":`)); err == nil || !errors.Is(err, ErrMalformed) {
		t.Fatal("incomplete JSON accepted", err)
	}
	if err := checkStrictJSON([]byte(`{} @`), new(struct{})); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatal(err)
	}
	if result := VerifyParsedExport(nil, nil, VerifyOptions{}); result.OK || result.Verdict != "FAIL" || len(result.Errors) == 0 {
		t.Fatal(result)
	}
}

func TestSummaryLimitationsBindExactInputAndFreshness(t *testing.T) {
	if got := summaryLimitationsV4(nil); got != nil {
		t.Fatal(got)
	}
	if got := summaryLimitationsV4(&SummaryLeafViewV4{Body: json.RawMessage(`{"limitations":["fixture limitation"]}`)}); len(got) != 1 || got[0] != "fixture limitation" {
		t.Fatal(got)
	}
	if limitationNamesV4([]string{"input-a latest_state: not_checked"}, "", "latest_state") {
		t.Fatal("empty input matched")
	}
	if limitationNamesV4([]string{"input-ab latest_state: not_checked"}, "input-a", "latest_state") {
		t.Fatal("identifier prefix matched")
	}
	if !limitationNamesV4([]string{"other statement", "input-a fixture-marker"}, "input-a", "fixture-marker") {
		t.Fatal("named marker not recognized")
	}
	for _, raw := range []string{"input-ab", "input-a_suffix"} {
		if limitationNamesInput(raw, "input-a") {
			t.Fatal("partial identifier matched", raw)
		}
	}
	if limitationNamesInput("unrelated words", "input-a") || limitationSaysLatestStateNotChecked("unrelated limitation") {
		t.Fatal("unrelated text supplied a limitation")
	}
	if got := mergeProducerAuth(labelVerified, labelFailed); got != labelFailed {
		t.Fatal("failure was weakened", got)
	}
	if got := mergeProducerAuth(labelVerified, "different"); got != labelNotChecked {
		t.Fatal("conflicting authorship was upgraded", got)
	}
}

func TestBundleHelpersRefuseInvalidMaterialBeforeTrustClaims(t *testing.T) {
	b, doc := buildReceiptBundleV4(t)
	res := newStandaloneResultV4()
	invalid := b
	invalid.ReceiptLeaf.Sequence = nil
	if checkBundleTrustV4(invalid, VerifyOptions{}, res) {
		t.Fatal("invalid envelope trusted")
	}
	if checkBundleBindingV4(invalid, res) {
		t.Fatal("incomplete parent binding accepted")
	}
	badSignature := b
	badSignature.Head.Signature = bytes.Repeat([]byte{1}, ed25519.SignatureSize)
	res = VerifyReceiptBundleV1(badSignature, VerifyOptions{Keyring: doc.signing.keyring(), ExpectedFinal: v4Pin(badSignature.Head)})
	if res.OK || res.AntiRollback == labelVerified {
		t.Fatal("a matching pin upgraded an invalid signature", res)
	}
	invalid = b
	invalid.ReceiptLeaf.LinkedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if checkBundleProofsV4(invalid, newStandaloneResultV4()) {
		t.Fatal("uncanonicalizable receipt proved")
	}
	invalid = b
	invalid.ReceiptLeaf.Leaf = strings.Repeat("0", 64)
	if checkBundleProofsV4(invalid, newStandaloneResultV4()) {
		t.Fatal("false receipt leaf claim proved")
	}
	leaf := newV4Builder(t).build()
	exp, err := LoadExportReader(strings.NewReader(leaf.text))
	if err != nil {
		t.Fatal(err)
	}
	if len(exp.Approvals) == 0 {
		t.Fatal("approval fixture missing")
	}
	approval := exp.Approvals[0]
	approval.LinkedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	result := VerifyStandaloneApprovalV4(approval, hash.InclusionProof{}, leaf.head, leaf.signing.id, VerifyOptions{Keyring: leaf.signing.keyring()})
	if result.OK {
		t.Fatal("uncanonicalizable approval verified")
	}
}

func TestAnchorPrefixRequiresDecisionSequenceAgreement(t *testing.T) {
	doc := newV4Builder(t).build()
	head := doc.head
	head.Index++
	head.Signature = ed25519.Sign(doc.signing.priv, HeadPayload(head))
	prefixes := map[uint64]prefixFact{head.TreeSize: {root: head.RootHash, hasDecision: true, lastDecision: head.Index - 1}}
	message := ""
	fail := func(format string, args ...any) bool { message = fmt.Sprintf(format, args...); return false }
	if checkExportAnchorPrefixV4(AnchorView{Head: head}, prefixes, 1, fail) || !strings.Contains(message, "last decision") {
		t.Fatal(message)
	}
	exp := &ExportFile{}
	exp.Header.Head = head
	result := &Result{AnchorsOK: true}
	checkExportAnchor(exp, result, VerifyOptions{}, doc.signing.pub, doc.leaves, head.LogID, 1, AnchorView{Head: head}, nil, nil, prefixes)
	if result.AnchorsOK || len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "last decision") {
		t.Fatal(result.Errors)
	}
}

func TestReferencedHeadIsReverifiedAgainstCurrentPinnedKey(t *testing.T) {
	doc := newV4Builder(t).build()
	wrong := newV4KeyPair("replacement", 23)
	input := SummaryInputV4{InputID: "input", KeyID: "key", Head: doc.head, Schema: ExportSchemaV4}
	exp := &ExportFile{}
	exp.Header.Head = doc.head
	cache := map[string]*parsedReference{"input": {exp: exp, res: &Result{OK: true}}}
	opts := VerifyOptions{SummaryReferences: []SummaryReferenceV4{{InputID: "input", Keyring: map[string]ed25519.PublicKey{"key": wrong.pub}}}}
	result := &Result{}
	ok, fresh := verifyReferencedInputV4(nil, result, opts, input, cache)
	if ok || fresh || len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "input head signature") {
		t.Fatal(ok, fresh, result.Errors)
	}
}

func TestFullSummaryCannotVerifyWithForgedPinnedProducer(t *testing.T) {
	b := newV4Builder(t)
	sum := validSummaryLeafTypedV4(t, b.tenant)
	b.specs = append(b.specs, v4SummarySpec(sum))
	b.localPrefixInputs = map[int]map[int]uint64{len(b.specs) - 1: {0: 1}}
	b.build()
	b.localPrefixInputs = nil
	sum.ChainHash, sum.Leaf = "claim", "claim"
	producer := newV4KeyPair("producer", 55)
	forger := newV4KeyPair("forger", 56)
	sum.ProducerSignature = &ProducerSignatureV4{Algorithm: HeadSignatureAlgorithm, KeyID: producer.id, Signature: bytes.Repeat([]byte{1}, ed25519.SignatureSize)}
	payload, err := sum.SummaryProducerPayloadV4()
	if err != nil {
		t.Fatal(err)
	}
	sum.ProducerSignature.Signature = ed25519.Sign(forger.priv, payload)
	doc := b.build()
	result := VerifyExportReaderResult(strings.NewReader(doc.text), nil, VerifyOptions{Keyring: doc.signing.keyring(), TrustedSummaryProducerKeys: producer.keyring()})
	if result.OK || result.SummaryProducerAuthorship != labelFailed || result.SummaryAncestry != labelFailed {
		t.Fatal("forged producer promoted to verified summary", result.Errors)
	}
}
