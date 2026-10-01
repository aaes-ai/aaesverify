package verifier

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStripAnchorsAndForgePreAnchorFailsByDefault(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 4)
	withAnchors := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: head}})
	stripped := stripAnchorLines(t, withAnchors)
	forged := setHeaderPreAnchor(t, stripped, true)

	res, err := VerifyExportReader(strings.NewReader(forged), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("stripped anchors with forged pre_anchor still verified: warnings=%v", res.Warnings)
	}
	joined := strings.Join(res.Errors, " ")
	if !strings.Contains(joined, "--allow-pre-anchor") {
		t.Fatalf("refusal does not name the opt-in: %v", res.Errors)
	}
}

func TestAllowPreAnchorAcceptsHonestPreAnchorExport(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 3)
	doc := exportJSONL(t, entries, head, pub)

	res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("honest pre_anchor export failed with AllowPreAnchor: %v", res.Errors)
	}
	joined := strings.Join(res.Warnings, " ")
	if !strings.Contains(joined, "pre_anchor") {
		t.Fatalf("pre_anchor export did not warn: %v", res.Warnings)
	}
}

func TestAllowPreAnchorAcceptsStrippedForgedPreAnchor(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 4)
	withAnchors := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: head}})
	stripped := stripAnchorLines(t, withAnchors)
	forged := setHeaderPreAnchor(t, stripped, true)

	res, err := VerifyExportReaderWithOptions(strings.NewReader(forged), pub, VerifyOptions{AllowPreAnchor: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("AllowPreAnchor did not accept forged pre_anchor export: %v", res.Errors)
	}
	joined := strings.Join(res.Warnings, " ")
	if !strings.Contains(joined, "pre_anchor") {
		t.Fatalf("AllowPreAnchor acceptance did not warn about pre_anchor: %v", res.Warnings)
	}
}

func TestAnchoredExportUnaffectedByAllowPreAnchor(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 2)
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: head}})

	for _, allow := range []bool{false, true} {
		res, err := VerifyExportReaderWithOptions(strings.NewReader(doc), pub, VerifyOptions{AllowPreAnchor: allow})
		if err != nil {
			t.Fatalf("AllowPreAnchor=%v: %v", allow, err)
		}
		if !res.OK {
			t.Fatalf("AllowPreAnchor=%v: anchored export failed: %v", allow, res.Errors)
		}
		if res.AnchorCount != 1 {
			t.Fatalf("AllowPreAnchor=%v: AnchorCount = %d, want 1", allow, res.AnchorCount)
		}
	}
}

func stripAnchorLines(t *testing.T, doc string) string {
	t.Helper()
	var kept []string
	for _, line := range strings.Split(doc, "\n") {
		if strings.Contains(line, `"type":"anchor"`) {
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		kept = append(kept, line)
	}
	if len(kept) == 0 {
		t.Fatal("fixture emptied after stripping anchors")
	}
	return strings.Join(kept, "\n") + "\n"
}

func setHeaderPreAnchor(t *testing.T, doc string, preAnchor bool) string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(doc, "\n"), "\n")
	if len(lines) == 0 {
		t.Fatal("empty export")
	}
	var hdr map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil {
		t.Fatal(err)
	}
	hdr["pre_anchor"] = preAnchor
	raw, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	lines[0] = string(raw)
	return strings.Join(lines, "\n") + "\n"
}
