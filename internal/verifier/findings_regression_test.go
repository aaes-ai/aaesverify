package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestExportRejectsDeclaredUnknownSignatureAlgorithms(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 3)
	for _, where := range []string{"header", "anchor"} {
		t.Run(where, func(t *testing.T) {
			doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: head}})
			lines := strings.Split(strings.TrimSpace(doc), "\n")
			for i, line := range lines {
				var object map[string]any
				if err := json.Unmarshal([]byte(line), &object); err != nil {
					t.Fatal(err)
				}
				if object["type"] == where {
					if where == "header" {
						object["signature_algorithm"] = "rsa"
					} else {
						object["algorithm"] = "rsa"
					}
					encoded, _ := json.Marshal(object)
					lines[i] = string(encoded)
				}
			}
			res := VerifyExportReaderResult(strings.NewReader(strings.Join(lines, "\n")+"\n"), pub, VerifyOptions{})
			if res.OK || res.Verdict != "FAIL" || !strings.Contains(strings.Join(res.Errors, " "), "rsa") {
				t.Fatalf("relabeled %s accepted: %+v", where, res)
			}
		})
	}
}

func TestEarlierPrefixTimestampCannotAttestPublishedHead(t *testing.T) {
	entries, final, pub, _ := buildLog(t, 3)
	_, prefix, _, _ := buildLog(t, 2)
	digest := sha256.Sum256(HeadPayload(prefix))
	_, cert, pool, key := testTSA(t)
	token := signedTSToken(t, digest[:], cert, key)
	anchor := AnchorView{Head: prefix, Timestamp: &TimestampView{Authority: "canary", Digest: hex.EncodeToString(digest[:]), Time: testTSGenTime, Token: token}}
	doc := exportJSONLWithAnchors(t, entries, final, pub, []AnchorView{anchor})
	res := VerifyExportReaderResult(strings.NewReader(doc), pub, VerifyOptions{TSARoots: pool})
	if !res.OK || res.TimestampsIndependent != 0 || res.IntegrityHeadline() != "CONSISTENT" {
		t.Fatalf("prefix became independent: %+v", res)
	}
	strict := VerifyExportReaderResult(strings.NewReader(doc), pub, VerifyOptions{TSARoots: pool, RequireIndependent: true})
	if strict.OK || strict.Verdict != "FAIL" {
		t.Fatal("require-independent accepted prefix timestamp")
	}
}

func TestUnparsedFailureHasVersionedJSONVerdict(t *testing.T) {
	for _, doc := range []string{"", "{broken\n"} {
		res := VerifyExportReaderResult(strings.NewReader(doc), nil, VerifyOptions{})
		if res.OK || res.Verdict != "FAIL" || res.ResultSchema != ResultSchemaV2 {
			t.Fatalf("unversioned failure: %+v", res)
		}
	}
}
