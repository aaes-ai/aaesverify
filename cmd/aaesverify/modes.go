package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/aaes-ai/aaesverify/internal/evaluation"
	"github.com/aaes-ai/aaesverify/internal/verifier"
)

// evidenceModes is the open verifier's tree-specific command line: the
// record/2 sidecar binding (--records, see RECORDS.md) and the disclosed
// evaluation directory (--evaluation). The monorepo keeps its own modes.go
// without them; sync.sh copies every other file of this command.
type evidenceModes struct {
	recordsPath    *string
	evaluationPath *string
}

func registerEvidenceModes(fs *flag.FlagSet) *evidenceModes {
	return &evidenceModes{
		recordsPath:    fs.String("records", "", "current record/2 sidecar to re-seal and bind to --export (see RECORDS.md)"),
		evaluationPath: fs.String("evaluation", "", "disclosed evaluation directory; authenticate artifacts, re-seal records and bind the v3 export"),
	}
}

// validate refuses mode combinations before any file is read.
func (m *evidenceModes) validate(exportPath, receiptPath string) error {
	records, evaluationDir := *m.recordsPath, *m.evaluationPath
	if receiptPath != "" && (evaluationDir != "" || records != "") {
		return errors.New("--receipt cannot be combined with --evaluation or --records")
	}
	if (evaluationDir != "" && (exportPath != "" || records != "")) || (records != "" && exportPath == "") {
		return errors.New("choose --export [--records] or --evaluation")
	}
	return nil
}

// standalone reports --evaluation, which replaces --export.
func (m *evidenceModes) standalone() bool { return *m.evaluationPath != "" }

// run verifies a disclosed evaluation directory.
func (m *evidenceModes) run(pubKey []byte, opts verifier.VerifyOptions, jsonOnly bool) int {
	result, err := evaluation.Verify(*m.evaluationPath, pubKey, opts)
	if err != nil {
		result = map[string]any{"schema": "aaes.disclosed-evaluation-verification/1", "ok": false, "verdict": "FAIL", "error": err.Error()}
	}
	if !jsonOnly {
		fmt.Println("Disclosed evaluation verification (omitted source and receipt-chain seals are outside this profile)")
		if err == nil && len(pubKey) == 0 {
			fmt.Println("warning: no --pubkey was supplied; the bundled signer key proves internal consistency only")
		}
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}

// bind re-seals a --records sidecar against the verified export and prints
// the combined result. It reports false when no sidecar was named.
func (m *evidenceModes) bind(parsed *verifier.ExportFile, res *verifier.Result, jsonOnly bool) (int, bool) {
	if *m.recordsPath == "" {
		return 0, false
	}
	count := 0
	if res.OK {
		raw, bindErr := evaluation.ReadRecordsFile(*m.recordsPath)
		if bindErr == nil {
			count, bindErr = evaluation.VerifyRecordsFile(parsed, raw)
		}
		if bindErr != nil {
			res.OK = false
			res.Verdict = "FAIL"
			res.Errors = append(res.Errors, bindErr.Error())
		}
	}
	result := map[string]any{"ok": res.OK, "verdict": res.Verdict, "sealed_records_resealed": res.OK, "sealed_sidecar_binding_verified": res.OK, "resealed_record_count": count, "receipt_chain_verified": false, "export": res}
	if !res.OK {
		result["verdict"] = "FAIL"
	}
	if !jsonOnly {
		fmt.Println("Record/2 re-sealing and export binding")
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return 1, true
	}
	if !res.OK {
		return 1, true
	}
	return 0, true
}
