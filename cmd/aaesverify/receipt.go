package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aaes-ai/aaesverify/internal/verifier"
)

type trustReceiptResult struct {
	OK                    bool     `json:"ok"`
	Schema                string   `json:"schema,omitempty"`
	Path                  string   `json:"path"`
	TenantID              string   `json:"tenant_id,omitempty"`
	Sequence              uint64   `json:"sequence,omitempty"`
	LogID                 string   `json:"log_id,omitempty"`
	Leaf                  string   `json:"leaf,omitempty"`
	LeafOK                bool     `json:"leaf_ok,omitempty"`
	InclusionOK           bool     `json:"inclusion_ok,omitempty"`
	HeadSignatureOK       bool     `json:"head_signature_ok,omitempty"`
	ClaimsOK              bool     `json:"claims_ok,omitempty"`
	AnchorPresent         bool     `json:"anchor_present"`
	AnchorHeadSignatureOK bool     `json:"anchor_head_signature_ok,omitempty"`
	Verdict               string   `json:"verdict"`
	Errors                []string `json:"errors,omitempty"`
}

func runTrustReceipt(path string, pubKey []byte, jsonOnly bool) int {
	res := &trustReceiptResult{Path: path, Verdict: "FAIL"}
	raw, err := os.ReadFile(path)
	if err != nil {
		err = fmt.Errorf("read receipt: %w", err)
	} else {
		var receipt verifier.TrustReceipt
		receipt, err = verifier.VerifyTrustReceipt(raw, pubKey)
		if err == nil {
			res.OK = true
			res.Schema = receipt.Schema
			res.TenantID = receipt.Entry.TenantID
			res.Sequence = receipt.Entry.Sequence
			res.LogID = receipt.Head.LogID
			res.Leaf = receipt.Leaf
			res.LeafOK = true
			res.InclusionOK = true
			res.HeadSignatureOK = true
			res.ClaimsOK = true
			res.AnchorPresent = receipt.Anchor != nil
			res.AnchorHeadSignatureOK = res.AnchorPresent
			res.Verdict = "CONSISTENT"
		}
	}
	if err != nil {
		res.Errors = []string{err.Error()}
	}
	if perr := printTrustReceiptResult(res, jsonOnly); perr != nil {
		fmt.Fprintf(os.Stderr, "aaesverify: %v\n", perr)
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "aaesverify: %v\n", err)
		return 1
	}
	return 0
}

func printTrustReceiptResult(res *trustReceiptResult, jsonOnly bool) error {
	if !jsonOnly {
		fmt.Println(renderTrustReceipt(res))
	}
	raw, err := json.Marshal(res)
	if !jsonOnly {
		fmt.Println("--- json ---")
	}
	fmt.Println(string(raw))
	return err
}

func renderTrustReceipt(res *trustReceiptResult) string {
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "%-22s %s\n", k+":", v) }
	line("receipt", res.Path)
	if res.OK {
		line("schema", res.Schema)
		line("tenant", res.TenantID)
		line("sequence", fmt.Sprintf("%d", res.Sequence))
		line("log id", res.LogID)
		line("leaf", fmt.Sprintf("%s (%s)", verdict(res.LeafOK), res.Leaf))
		line("inclusion proof", verdict(res.InclusionOK))
		line("head signature", fmt.Sprintf("%s (against supplied public key; key provenance not verified)", verdict(res.HeadSignatureOK)))
		line("claims", fmt.Sprintf("%s (decision commitment only; no execution or completeness claim)", verdict(res.ClaimsOK)))
		if res.AnchorPresent {
			line("anchor", fmt.Sprintf("present, head signature %s, witnesses not checked", verdict(res.AnchorHeadSignatureOK)))
		} else {
			line("anchor", "absent")
		}
	}
	for _, err := range res.Errors {
		line("error", err)
	}
	line("result", res.Verdict)
	return strings.TrimRight(b.String(), "\n")
}
