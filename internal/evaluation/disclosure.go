// SPDX-License-Identifier: Apache-2.0
// Package evaluation checks a fixed partial-disclosure profile without importing
// the producer. Current sealed records are re-sealed and bound; omitted source is not verified.
package evaluation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/aaes-ai/aaesverify/internal/verifier"
)

const ManifestSchema = "aaes.framework-evaluation/1"
const DisclosureSchema = "aaes.evaluation-disclosure/1"
const maxFileBytes = 16 << 20

// Files is the complete evidence-only profile. Source, producer binaries and
// private build records cannot be introduced through an edited disclosure list.
func Files() []string {
	return []string{"cases.json", "configuration.json", "dependencies.lock", "execution-plan.json", "http-transcript.json", "limits.json", "provider-calls.json", "results.json", "evidence/MANIFEST.json", "evidence/SHA256SUMS", "evidence/export.jsonl", "evidence/ledger.pub", "evidence/records.jsonl"}
}

type Disclosure struct {
	Schema   string   `json:"schema"`
	Included []string `json:"included"`
	Omitted  []string `json:"omitted"`
}

type manifest struct {
	Schema       string            `json:"schema"`
	SuiteVersion string            `json:"suite_version"`
	Provider     string            `json:"provider"`
	Files        map[string]string `json:"files"`
}

// Verify authenticates the original manifest and all disclosed bytes, and checks
// the v3 export using the candidate reader. A nil pin uses the bundled key only.
func Verify(dir string, pin ed25519.PublicKey, options verifier.VerifyOptions) (map[string]any, error) {
	read := func(name string) ([]byte, error) { return readRegular(dir, name) }
	raw, err := read("evaluation.json")
	if err != nil {
		return nil, err
	}
	var man manifest
	if err := decodeUnique(raw, &man); err != nil {
		return nil, fmt.Errorf("evaluation manifest: %w", err)
	}
	if man.Schema != ManifestSchema || man.SuiteVersion == "" || len(man.Files) == 0 {
		return nil, fmt.Errorf("unsupported or empty evaluation manifest")
	}
	for name, value := range man.Files {
		if !safePath(name) || !validHash(value) {
			return nil, fmt.Errorf("invalid signed artifact path/hash: %q", name)
		}
	}
	keyRaw, err := read("evidence/ledger.pub")
	if err != nil {
		return nil, err
	}
	key, err := verifier.ParsePublicKey(string(keyRaw))
	if err != nil {
		return nil, err
	}
	pinned := len(pin) != 0
	if pinned && !bytes.Equal(pin, key) {
		return nil, fmt.Errorf("trusted key differs from bundled evaluation key")
	}
	sigRaw, err := read("evaluation.sig")
	if err != nil {
		return nil, err
	}
	signature, err := hex.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil || !ed25519.Verify(key, append([]byte(ManifestSchema+"\n"), raw...), signature) {
		return nil, fmt.Errorf("evaluation manifest signature failed")
	}
	disclosureRaw, err := read("disclosure.json")
	if err != nil {
		return nil, err
	}
	var disclosure Disclosure
	if err := decodeUnique(disclosureRaw, &disclosure); err != nil {
		return nil, err
	}
	expected := map[string]bool{"evaluation.json": true, "evaluation.sig": true, "disclosure.json": true}
	included := map[string]bool{}
	for _, name := range Files() {
		included[name] = true
		expected[name] = true
	}
	if disclosure.Schema != DisclosureSchema || !sameSet(disclosure.Included, included) {
		return nil, fmt.Errorf("disclosed files must match the fixed evidence-only profile")
	}
	omitted := map[string]bool{}
	for name := range man.Files {
		if !included[name] {
			omitted[name] = true
		}
	}
	if !sameSet(disclosure.Omitted, omitted) {
		return nil, fmt.Errorf("omission list differs from original signed manifest")
	}
	if err := exactInventory(dir, expected); err != nil {
		return nil, err
	}
	for name := range included {
		data, err := read(name)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		if man.Files[name] != hex.EncodeToString(sum[:]) {
			return nil, fmt.Errorf("disclosed artifact hash mismatch: %s", name)
		}
	}
	configurationRaw, err := read("configuration.json")
	if err != nil {
		return nil, err
	}
	var configuration struct {
		Provider string `json:"provider"`
	}
	if err := decodeUnique(configurationRaw, &configuration); err != nil {
		return nil, fmt.Errorf("configuration metadata: %w", err)
	}
	if !regexp.MustCompile(`^aaes\.local-provider/[1-9][0-9]*$`).MatchString(man.Provider) || man.Provider != configuration.Provider {
		return nil, fmt.Errorf("simulator provider metadata mismatch or invalid version")
	}
	exportRaw, err := read("evidence/export.jsonl")
	if err != nil {
		return nil, err
	}
	export := verifier.VerifyExportReaderResult(bytes.NewReader(exportRaw), key, options)
	if !export.OK {
		return nil, fmt.Errorf("export verification failed: %v", export.Errors)
	}
	if export.Schema != verifier.ExportSchemaV3 {
		return nil, fmt.Errorf("external evaluation profile requires a v3 export")
	}
	recordsRaw, err := read("evidence/records.jsonl")
	if err != nil {
		return nil, err
	}
	resealed, err := VerifyRecords(exportRaw, recordsRaw)
	if err != nil {
		return nil, err
	}
	omissions := append([]string(nil), disclosure.Omitted...)
	sort.Strings(omissions)
	return map[string]any{
		"schema": "aaes.disclosed-evaluation-verification/1", "ok": true, "verdict": export.Verdict,
		"manifest_signature_ok": true, "disclosed_artifact_hashes_ok": true,
		"provider": man.Provider, "provider_metadata_consistent": true,
		"disclosed_artifact_count": len(included), "omitted_artifacts": omissions,
		"signer_key_pinned": pinned, "full_private_bundle_verified": false,
		"sealed_sidecar_bytes_authenticated": true, "sealed_sidecar_binding_verified": true,
		"sealed_records_resealed": true, "resealed_record_count": resealed, "receipt_chain_verified": false,
		"independent_attestation": export.IndependentAttestation(), "export": export,
	}, nil
}

func validHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func safePath(name string) bool {
	if !fs.ValidPath(name) || !filepath.IsLocal(name) || strings.ContainsAny(name, "\\\x00\r\n\t:") {
		return false
	}
	return name != "."
}

func readRegular(root, name string) ([]byte, error) {
	if !safePath(name) {
		return nil, fmt.Errorf("unsafe disclosure path: %q", name)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("disclosure root must be a regular directory")
	}
	path := root
	parts := strings.Split(name, "/")
	for i, part := range parts {
		path = filepath.Join(path, part)
		info, err = os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || (i == len(parts)-1 && !info.Mode().IsRegular()) || (i < len(parts)-1 && !info.IsDir()) {
			return nil, fmt.Errorf("nonregular disclosure path: %s", name)
		}
	}
	if info.Size() > maxFileBytes {
		return nil, fmt.Errorf("disclosed file exceeds size limit: %s", name)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if len(raw) > maxFileBytes {
		return nil, fmt.Errorf("disclosed file exceeds size limit: %s", name)
	}
	return raw, err
}

func exactInventory(root string, expected map[string]bool) error {
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in disclosure")
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !entry.Type().IsRegular() || !expected[rel] {
			return fmt.Errorf("unexpected disclosure artifact: %s", rel)
		}
		seen[rel] = true
		return nil
	})
	if err != nil {
		return err
	}
	for name := range expected {
		if !seen[name] {
			return fmt.Errorf("missing disclosure artifact: %s", name)
		}
	}
	return nil
}

func sameSet(values []string, expected map[string]bool) bool {
	if len(values) != len(expected) {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !expected[value] || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

// Reject duplicate object keys before typed decoding, including nested objects.
func decodeUnique(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func() error
	depth := 0
	walk = func() error {
		depth++
		defer func() { depth-- }()
		if depth > 128 {
			return fmt.Errorf("JSON nesting exceeds disclosure limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if delim != '{' && delim != '[' {
			return fmt.Errorf("unexpected JSON delimiter")
		}
		seen := map[string]bool{}
		for decoder.More() {
			if delim == '{' {
				token, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok || seen[key] {
					return fmt.Errorf("duplicate or invalid JSON key: %v", token)
				}
				seen[key] = true
			}
			if err := walk(); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return json.Unmarshal(raw, value)
}
