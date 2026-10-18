package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/aaes-ai/aaesverify/internal/verifier"
)

func validateCommandMode(exportPath, receiptPath, pubPath, tsaRootsPath, witnessTrustPath string, requireIndependent, allowPreAnchor bool) error {
	if receiptPath == "" {
		if exportPath == "" {
			return errors.New("--export is required (or --receipt)")
		}
		return nil
	}
	if exportPath != "" {
		return errors.New("--export and --receipt are mutually exclusive")
	}
	if pubPath == "" {
		return errors.New("--pubkey is required with --receipt")
	}
	if tsaRootsPath != "" || witnessTrustPath != "" || requireIndependent || allowPreAnchor {
		return errors.New("independence and pre-anchor flags apply only to --export")
	}
	return nil
}

func loadCommandPublicKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	return verifier.ParsePublicKey(string(raw))
}
