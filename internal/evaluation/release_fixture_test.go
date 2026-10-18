// SPDX-License-Identifier: Apache-2.0
package evaluation

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/aaes-ai/aaesverify/internal/verifier"
)

// AAES_RELEASE_FIXTURE_OUT is an explicit maintainer-only export hook. It writes
// disposable synthetic public fixtures, never the generated signing private key.
// Normal test runs verify the fixture without exporting it.
func TestReleaseSmokeFixture(t *testing.T) {
	root, key := fixture(t)
	result, err := Verify(root, key, verifier.VerifyOptions{})
	if err != nil || result["resealed_record_count"] != 1 {
		t.Fatalf("synthetic fixture: %v %v", result, err)
	}
	destination := os.Getenv("AAES_RELEASE_FIXTURE_OUT")
	if destination == "" {
		return
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("fixture output already exists or cannot be checked")
	}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0644)
	}); err != nil {
		t.Fatal(err)
	}
}
