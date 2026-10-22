// SPDX-License-Identifier: Apache-2.0
package evaluation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aaes-ai/aaesverify/internal/verifier"
)

func write(t *testing.T, root, name string, data []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func encode(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func fixture(t *testing.T) (string, ed25519.PublicKey) {
	return fixtureWithProvider(t, "aaes.local-provider/2", "aaes.local-provider/2")
}

func fixtureWithProvider(t *testing.T, manifestProvider, configurationProvider string) (string, ed25519.PublicKey) {
	t.Helper()
	root := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	export, sidecar := syntheticEvidence(t, pub, priv)
	files := map[string]string{}
	for _, name := range Files() {
		raw := []byte("{}\n")
		if name == "configuration.json" {
			raw = encode(t, map[string]string{"provider": configurationProvider})
		}
		if name == "evidence/export.jsonl" {
			raw = export
		}
		if name == "evidence/records.jsonl" {
			raw = sidecar
		}
		if name == "evidence/ledger.pub" {
			raw = []byte(hex.EncodeToString(pub) + "\n")
		}
		write(t, root, name, raw)
		sum := sha256.Sum256(raw)
		files[name] = hex.EncodeToString(sum[:])
	}
	files["sources/omitted.go"] = strings.Repeat("a", 64)
	raw := encode(t, map[string]any{"schema": ManifestSchema, "suite_version": "1.0.0", "provider": manifestProvider, "files": files})
	write(t, root, "evaluation.json", raw)
	write(t, root, "evaluation.sig", []byte(hex.EncodeToString(ed25519.Sign(priv, append([]byte(ManifestSchema+"\n"), raw...)))))
	write(t, root, "disclosure.json", encode(t, Disclosure{Schema: DisclosureSchema, Included: Files(), Omitted: []string{"sources/omitted.go"}}))
	return root, pub
}

func TestDisclosedV3EvidenceAndHonestScope(t *testing.T) {
	root, key := fixture(t)
	for _, pin := range []ed25519.PublicKey{nil, key} {
		result, err := Verify(root, pin, verifier.VerifyOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if result["ok"] != true || result["verdict"] != "CONSISTENT" || result["sealed_sidecar_bytes_authenticated"] != true || result["sealed_sidecar_binding_verified"] != true || result["sealed_records_resealed"] != true || result["resealed_record_count"] != 1 || result["full_private_bundle_verified"] != false || result["signer_key_pinned"] != (len(pin) != 0) {
			t.Fatalf("incorrect scope: %#v", result)
		}
	}
	if _, err := Verify(root, make([]byte, 32), verifier.VerifyOptions{}); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := Verify(root, nil, verifier.VerifyOptions{RequireIndependent: true}); err == nil {
		t.Fatal("unwitnessed evidence accepted as independent")
	}
}

func TestDisclosureMutationsFailClosed(t *testing.T) {
	for _, mutation := range []string{"artifact", "manifest", "signature", "omissions", "missing", "extra", "symlink", "duplicate_json"} {
		t.Run(mutation, func(t *testing.T) {
			root, _ := fixture(t)
			switch mutation {
			case "artifact":
				write(t, root, "evidence/records.jsonl", []byte("changed\n"))
			case "manifest":
				write(t, root, "evaluation.json", []byte(`{"schema":"forged"}`))
			case "signature":
				write(t, root, "evaluation.sig", []byte(strings.Repeat("0", 128)))
			case "omissions":
				write(t, root, "disclosure.json", encode(t, Disclosure{Schema: DisclosureSchema, Included: Files()}))
			case "missing":
				if err := os.Remove(filepath.Join(root, "results.json")); err != nil {
					t.Fatal(err)
				}
			case "extra":
				write(t, root, "producer.go", []byte("package forbidden\n"))
			case "duplicate_json":
				write(t, root, "disclosure.json", []byte(`{"schema":"x","schema":"aaes.evaluation-disclosure/1"}`))
			case "symlink":
				file := filepath.Join(root, "results.json")
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("cases.json", file); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			if _, err := Verify(root, nil, verifier.VerifyOptions{}); err == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
}

func TestUniqueJSONAndSafePaths(t *testing.T) {
	for _, raw := range []string{`{"files":{"a":1,"a":2}}`, `{} {}`, `{"a":[{"b":1,"b":2}]}`} {
		var out any
		if err := decodeUnique([]byte(raw), &out); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	for _, raw := range []string{`true`, `false`, `0`, `"scalar"`, `[]`, `null`} {
		var object map[string]json.RawMessage
		if err := decodeUnique([]byte(raw), &object); err == nil {
			t.Fatalf("accepted non-object %s", raw)
		}
	}
	var object map[string]json.RawMessage
	if err := decodeUnique([]byte(`{"kept":1}`), &object); err != nil || string(object["kept"]) != "1" {
		t.Fatalf("object capture: %v %#v", err, object)
	}
	for _, name := range []string{"../escape", "/absolute", "a\\b", "a\nb", "C:/drive", "."} {
		if safePath(name) {
			t.Fatalf("unsafe path accepted: %q", name)
		}
	}
}

func TestSignedProviderMetadataMustAgree(t *testing.T) {
	for _, pair := range [][2]string{{"aaes.local-provider/1", "aaes.local-provider/2"}, {"", ""}, {"aaes.local-provider/0", "aaes.local-provider/0"}, {"aaes.local-provider/02", "aaes.local-provider/02"}, {"other/2", "other/2"}} {
		root, key := fixtureWithProvider(t, pair[0], pair[1])
		if _, err := Verify(root, key, verifier.VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "provider metadata") {
			t.Fatalf("validly signed metadata %v did not fail semantic check: %v", pair, err)
		}
	}
	root, key := fixtureWithProvider(t, "aaes.local-provider/3", "aaes.local-provider/3")
	result, err := Verify(root, key, verifier.VerifyOptions{})
	if err != nil || result["provider_metadata_consistent"] != true || result["provider"] != "aaes.local-provider/3" {
		t.Fatalf("version not propagated: %v %v", result, err)
	}
}
