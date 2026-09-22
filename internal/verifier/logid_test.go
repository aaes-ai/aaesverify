package verifier

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/aaes-dev/aaesverify/internal/hash"
)

// relabelledHead returns a copy of the fixture head carrying the log id of a
// DIFFERENT tenant, correctly re-signed by the ledger's own key. That is the
// exact shape a cross-log splice produces: every signature on the file is
// valid, and the head's log id is the only thing that says which log the
// evidence belongs to.
func relabelledHead(t *testing.T, head hash.TreeHead, logID string) hash.TreeHead {
	t.Helper()
	forged := head
	forged.LogID = logID
	forged.Signature = nil
	forged.Signature = ed25519.Sign(testPriv(), HeadPayload(forged))
	return forged
}

// The named errors are part of the contract: a caller must be able to tell a
// legacy head (written before log ids existed) from a relabelled one by
// errors.Is, not by parsing a message.
func TestHeadLogIDErrorsAreNamed(t *testing.T) {
	want := hash.DeriveLogID("tenant-a")
	if err := checkHeadLogID(hash.TreeHead{}, want); !errors.Is(err, ErrLegacyHead) {
		t.Fatalf("empty log id = %v, want ErrLegacyHead", err)
	}
	foreign := hash.TreeHead{LogID: hash.DeriveLogID("tenant-b")}
	if err := checkHeadLogID(foreign, want); !errors.Is(err, ErrLogIDMismatch) {
		t.Fatalf("foreign log id = %v, want ErrLogIDMismatch", err)
	}
	mine := hash.TreeHead{LogID: want}
	if err := checkHeadLogID(mine, want); err != nil {
		t.Fatalf("matching log id = %v, want nil", err)
	}
}

func TestPublishedHeadFromAnotherLogIsRejected(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 3)
	foreign := relabelledHead(t, head, hash.DeriveLogID("tenant-b"))
	doc := exportJSONL(t, entries, foreign, pub)
	res, err := VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("an export whose published head names another log verified: %+v", res)
	}
	if !strings.Contains(strings.Join(res.Errors, " "), "log_id") {
		t.Fatalf("the refusal does not name the log id: %v", res.Errors)
	}
}

// The anchor commits to the same tree size and root as the final head, so
// before the log-id check existed it verified as an anchor of this export
// while belonging to another log. This is the replay C56 describes.
func TestAnchorFromAnotherLogIsRejected(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 4)
	foreign := relabelledHead(t, head, hash.DeriveLogID("tenant-b"))
	doc := exportJSONLWithAnchors(t, entries, head, pub, []AnchorView{{Head: foreign}})
	res, err := VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("a foreign-log anchor verified: %+v", res)
	}
	if res.AnchorsOK {
		t.Fatal("anchors_ok stayed true for an anchor from another log")
	}
	if !strings.Contains(strings.Join(res.Errors, " "), "log_id") {
		t.Fatalf("the refusal does not name the log id: %v", res.Errors)
	}
}

// A head with no log id at all — the legacy pre-log-id shape, here signed
// fresh so the signature itself is valid — must fail with the legacy error
// rather than pass as if it named no particular log.
func TestLegacyHeadWithoutALogIDFailsVerification(t *testing.T) {
	entries, head, pub, _ := buildLog(t, 3)
	legacy := relabelledHead(t, head, "")
	doc := exportJSONL(t, entries, legacy, pub)
	res, err := VerifyExportReader(strings.NewReader(doc), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("a head with no log id verified: %+v", res)
	}
	if !strings.Contains(strings.Join(res.Errors, " "), "predates log ids") {
		t.Fatalf("the refusal does not name the legacy head: %v", res.Errors)
	}
}
