package main

import (
	"path/filepath"
	"testing"
)

// The open verifier reads the export fixtures from testdata/; the monorepo
// keeps its own fixtures_test.go pointing at internal/store_versions.

func fixtureExport(t *testing.T) string {
	t.Helper()
	return filepath.Join(moduleDir(t), "testdata", "export_v2.jsonl")
}

func fixturePubKeyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(moduleDir(t), "testdata", "public_key.hex")
}

// exportFixturePath is a v2 export with its ledger key embedded.
func exportFixturePath(t *testing.T) string {
	t.Helper()
	return fixtureExport(t)
}
