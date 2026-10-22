package verifier

import "github.com/aaes-ai/aaesverify/internal/hash"

// checkLegacyHeadSchemas refuses a v2 or v3 export whose signed heads name a
// schema. Those heads omit the member, and the header label is not signed, so a
// head that signs "aaes.export/v4" under a v2/v3 header is a relabelled v4
// export and must not escape the v4 verdict rules on the legacy path.
func checkLegacyHeadSchemas(exp *ExportFile, res *Result) {
	heads := make([]hash.TreeHead, 0, len(exp.Anchors)+1)
	heads = append(heads, exp.Header.Head)
	for _, anchor := range exp.Anchors {
		heads = append(heads, anchor.Head)
	}
	for i, head := range heads {
		if head.Schema != "" {
			res.addError("signed head %d names schema %q under a %q header; the header is not signed, so the export is treated as relabelled", i, head.Schema, exp.Header.Schema)
		}
	}
}
