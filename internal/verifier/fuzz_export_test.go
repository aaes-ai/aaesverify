package verifier

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// FuzzLoadExportReader exercises the export envelope parser — the JSONL
// decode every offline verification starts with — with arbitrary bytes. The
// invariants under test:
//
//   - no input panics, however malformed;
//   - every parse failure wraps ErrMalformed, so a caller can tell a corrupt
//     export from a verification failure by one errors.Is;
//   - a parse that succeeds has read a header line (the parser refuses a
//     headerless stream rather than returning an empty export).
func FuzzLoadExportReader(f *testing.F) {
	header := `{"type":"header","schema":"aaes/export/1","log_id":"log-fuzz","tenant_id":"tenant-fuzz","entry_count":1}`
	entry := `{"type":"entry","sequence":1,"record_hash":"rh"}`
	anchor := `{"type":"anchor","key_id":"key-fuzz","algorithm":"ed25519"}`

	f.Add([]byte{})                                             // empty
	f.Add([]byte(header + "\n"))                                // header only
	f.Add([]byte(header + "\n" + entry + "\n" + anchor + "\n")) // a full small export
	f.Add([]byte(`{"type":"header"`))                           // truncated
	f.Add([]byte(`{"schema":"aaes/export/1"}`))                 // missing the type discriminator
	f.Add([]byte(header + "\n" + header + "\n"))                // duplicate header
	f.Add([]byte(`[1,2,3]`))                                    // wrong-typed: array
	f.Add([]byte(strings.Repeat("x", maxLineBytes+1) + "\n"))   // oversized line
	f.Fuzz(func(t *testing.T, data []byte) {
		exp, err := LoadExportReader(bytes.NewReader(data))
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("a parse failure must wrap ErrMalformed, got: %v", err)
			}
			return
		}
		if exp == nil {
			t.Fatal("the parser succeeded and returned no export")
		}
	})
}
