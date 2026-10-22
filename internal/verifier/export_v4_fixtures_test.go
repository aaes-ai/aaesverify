package verifier

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aaes-ai/aaesverify/internal/hash"
	"github.com/aaes-ai/aaesverify/internal/types"
)

// Programmatic v4 fixtures: leaves are constructed as typed values, the real
// preimages, chain and root are computed with the hash package, and heads are
// signed with generated ed25519 keys, so every refusal test starts from an
// export that verifies but for the one guard under test.

var v4Base = time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

// v4KeyPair is a labeled ed25519 keypair; the label is the keyring key_id.
type v4KeyPair struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newV4KeyPair(id string, seed byte) *v4KeyPair {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	return &v4KeyPair{id: id, pub: priv.Public().(ed25519.PublicKey), priv: priv}
}

func (k *v4KeyPair) keyring() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{k.id: k.pub}
}

// mergeKeyringsV4 unions keyrings; fixture keys have distinct ids.
func mergeKeyringsV4(keys ...*v4KeyPair) map[string]ed25519.PublicKey {
	out := map[string]ed25519.PublicKey{}
	for _, k := range keys {
		out[k.id] = k.pub
	}
	return out
}

func v4str(s string) *string         { return &s }
func v4timep(t time.Time) *time.Time { return &t }
func v4boolp(b bool) *bool           { return &b }
func v4uintp(u uint64) *uint64       { return &u }

// v4Entry is a decision entry with deterministic content.
func v4Entry(tenant string, seq uint64, at time.Time) EntryView {
	return EntryView{
		TenantID:   tenant,
		Sequence:   seq,
		RecordHash: hash.SHA256Hex([]byte(fmt.Sprintf("record-%s-%d", tenant, seq))),
		IntentID:   fmt.Sprintf("intent-%s-%d", tenant, seq),
		ActorID:    "agent-1",
		Capability: "payments.transfer",
		Tier:       types.R3RiskTier,
		Allowed:    true,
		GrantID:    fmt.Sprintf("grant-%d", seq),
		OccurredAt: at,
		LinkedAt:   at,
	}
}

// v4ReceiptLeaf is a receipt bound to parent with the nested fields agreeing.
func v4ReceiptLeaf(parent EntryView, id string, class types.EffectClass, linkedAt time.Time) *ReceiptLeafViewV4 {
	return &ReceiptLeafViewV4{
		Type:       lineReceiptV4,
		Schema:     ExportSchemaV4,
		Sequence:   v4uintp(parent.Sequence),
		RecordHash: parent.RecordHash,
		LinkedAt:   linkedAt,
		Receipt: ReceiptV4{
			ReceiptID:     v4str(id),
			IntentID:      v4str(parent.IntentID),
			TenantID:      v4str(parent.TenantID),
			RecordHash:    v4str(parent.RecordHash),
			GrantID:       v4str(parent.GrantID),
			IssuedAt:      v4timep(linkedAt.Add(-time.Minute)),
			Class:         &class,
			RailConfirmed: v4boolp(true),
			ConfirmedAt:   v4timep(time.Time{}),
			ReportedAt:    v4timep(time.Time{}),
			ObservedAt:    v4timep(time.Time{}),
		},
	}
}

// v4ApprovalPending is the first record of a valid approval history.
func v4ApprovalPending(id, tenant string, sourceSeq uint64, at time.Time) *ApprovalLeafViewV4 {
	kind := types.ApproverHuman
	auth := types.AuthorityGranted
	state := types.ApprovalPending
	src := types.ManagerSourceLegacy
	return &ApprovalLeafViewV4{
		Type:           lineApprovalV4,
		Schema:         ExportSchemaV4,
		SourceSequence: v4uintp(sourceSeq),
		LinkedAt:       at,
		Approval: ApprovalV4{
			ApprovalID:              v4str(id),
			TenantID:                v4str(tenant),
			TaskID:                  v4str("task-1"),
			IntentID:                v4str("intent-1"),
			Requester:               v4str("agent-1"),
			InitiatedBy:             v4str("agent-1"),
			Approver:                v4str(""),
			State:                   &state,
			Reason:                  v4str(""),
			PayloadHash:             v4str("ph-1"),
			BundleHash:              v4str("bh-1"),
			EngineVersion:           v4str("ev-1"),
			CreatedAt:               v4timep(at),
			ExpiresAt:               v4timep(at.Add(24 * time.Hour)),
			DecidedAt:               v4timep(time.Time{}),
			ApproverKind:            &kind,
			ApproverAuthority:       &auth,
			RequesterManagersSource: &src,
			Action:                  v4str("pay"),
		},
	}
}

// v4ApprovalExpired derives the expired successor of a pending record,
// preserving every raise fact.
func v4ApprovalExpired(pending *ApprovalLeafViewV4, sourceSeq uint64, at time.Time) *ApprovalLeafViewV4 {
	out := *pending
	a := out.Approval
	state := types.ApprovalExpired
	a.State = &state
	out.Approval = a
	out.SourceSequence = v4uintp(sourceSeq)
	out.LinkedAt = at
	return &out
}

// v4ApprovalPendingGrowth derives the pending→pending successor that grows
// the manager set, preserving every raise fact.
func v4ApprovalPendingGrowth(pending *ApprovalLeafViewV4, sourceSeq uint64, at time.Time, managers []ManagerEntryV4) *ApprovalLeafViewV4 {
	out := *pending
	a := out.Approval
	a.RequesterManagers = managers
	out.Approval = a
	out.SourceSequence = v4uintp(sourceSeq)
	out.LinkedAt = at
	return &out
}

// v4ApprovalGranted derives the granted successor of a pending record,
// preserving every raise fact.
func v4ApprovalGranted(pending *ApprovalLeafViewV4, sourceSeq uint64, approver string, decidedAt time.Time) *ApprovalLeafViewV4 {
	out := *pending
	a := out.Approval
	state := types.ApprovalGranted
	a.State = &state
	a.Approver = v4str(approver)
	a.DecidedAt = v4timep(decidedAt)
	out.Approval = a
	out.SourceSequence = v4uintp(sourceSeq)
	out.LinkedAt = decidedAt
	return &out
}

// v4Manager is one RequesterManagers element.
func v4Manager(actorID string, kind types.ActorKind, role types.ManagerRole, primary bool) ManagerEntryV4 {
	return ManagerEntryV4{ActorID: v4str(actorID), Kind: &kind, Role: &role, Primary: v4boolp(primary)}
}

// v4Spec is one leaf under construction; exactly one member is set.
type v4Spec struct {
	entry    *EntryView
	receipt  *ReceiptLeafViewV4
	approval *ApprovalLeafViewV4
	summary  *SummaryLeafViewV4
}

func v4EntrySpec(e EntryView) v4Spec            { return v4Spec{entry: &e} }
func v4ReceiptSpec(r *ReceiptLeafViewV4) v4Spec { return v4Spec{receipt: r} }
func v4ApprovalSpec(a *ApprovalLeafViewV4) v4Spec {
	return v4Spec{approval: a}
}

// v4AnchorSpec describes one anchor to build over a prefix of the export's
// computed leaves.
type v4AnchorSpec struct {
	key       *v4KeyPair
	treeSize  uint64
	legacy    bool // build the head without signed schema (historical anchor)
	omitKeyID bool
	// mutate runs before signing, for heads that must verify or fail in a
	// specific way.
	mutate    func(*hash.TreeHead)
	witnesses []v4WitnessSpec
}

type v4WitnessSpec struct {
	id  string
	key *v4KeyPair
}

// v4ExportBuilder builds a complete v4 export.
type v4ExportBuilder struct {
	t         *testing.T
	tenant    string
	exported  time.Time
	preAnchor bool
	embedKey  bool
	signing   *v4KeyPair
	specs     []v4Spec
	anchors   []v4AnchorSpec
	// mutateHead runs before signing; headSignature overrides the signature
	// outright (the recompute-all-keep-signature forgery case).
	mutateHead    func(*hash.TreeHead)
	headSignature []byte
	// mutateHeader runs on the rendered header map.
	mutateHeader func(map[string]any)
	// localPrefixInputs marks summary inputs — spec index to input index to
	// prefix tree size — whose heads the build replaces with genuine signed
	// local-prefix heads (design section 5.3), so a summary fixture can carry
	// a verifiable input over a prior state of the same log.
	localPrefixInputs map[int]map[int]uint64
}

// newV4Builder is a valid minimal export: two decisions, one receipt on the
// second, one pending approval, pre-anchor with the flag inside the signed
// head.
func newV4Builder(t *testing.T) *v4ExportBuilder {
	t.Helper()
	e1 := v4Entry("tenant-a", 1, v4Base)
	e2 := v4Entry("tenant-a", 2, v4Base.Add(time.Minute))
	return &v4ExportBuilder{
		t:         t,
		tenant:    "tenant-a",
		exported:  v4Base.Add(time.Hour),
		preAnchor: true,
		embedKey:  true,
		signing:   newV4KeyPair("ledger-k1", 11),
		specs: []v4Spec{
			v4EntrySpec(e1),
			v4EntrySpec(e2),
			v4ReceiptSpec(v4ReceiptLeaf(e2, "rc-1", types.EffectExecuted, v4Base.Add(2*time.Minute))),
			v4ApprovalSpec(v4ApprovalPending("ap-1", "tenant-a", 17, v4Base.Add(3*time.Minute))),
		},
	}
}

// v4Built is the rendered export plus every derived value a test needs.
type v4Built struct {
	text    string
	head    hash.TreeHead
	leaves  []string
	chains  []string
	signing *v4KeyPair
	// anchorHeads are the heads exactly as emitted on the anchor lines.
	anchorHeads []hash.TreeHead
}

func (b *v4ExportBuilder) leafClaims() (preimages [][]byte, leaves, chains []string, lastEntrySeq uint64) {
	prev := ""
	for _, s := range b.specs {
		pre := v4SpecPreimage(b.t, s)
		chain := hash.Chain(prev, pre)
		preimages = append(preimages, pre)
		leaves = append(leaves, hash.SHA256Hex(pre))
		chains = append(chains, chain)
		prev = chain
		if s.entry != nil {
			lastEntrySeq = s.entry.Sequence
		}
	}
	return preimages, leaves, chains, lastEntrySeq
}

// v4SpecPreimage computes the real preimage of one spec. PreimageV4 validates
// the whole envelope, including the exporter-claim members that the builder
// fills only after the preimage exists — the claims are excluded from the
// preimage, so placeholder values satisfy the validation without changing the
// bytes.
func v4SpecPreimage(t *testing.T, s v4Spec) []byte {
	t.Helper()
	var pre []byte
	var err error
	switch {
	case s.entry != nil:
		pre, err = s.entry.preimage()
	case s.receipt != nil:
		r := *s.receipt
		if r.ChainHash == "" {
			r.ChainHash = "fixture-claim"
		}
		if r.Leaf == "" {
			r.Leaf = "fixture-claim"
		}
		pre, err = r.PreimageV4()
	case s.approval != nil:
		a := *s.approval
		if a.ChainHash == "" {
			a.ChainHash = "fixture-claim"
		}
		if a.Leaf == "" {
			a.Leaf = "fixture-claim"
		}
		pre, err = a.PreimageV4()
	case s.summary != nil:
		sum := *s.summary
		if sum.ChainHash == "" {
			sum.ChainHash = "fixture-claim"
		}
		if sum.Leaf == "" {
			sum.Leaf = "fixture-claim"
		}
		pre, err = sum.PreimageV4()
	default:
		t.Fatal("v4Spec with no leaf")
	}
	if err != nil {
		t.Fatalf("fixture preimage: %v", err)
	}
	return pre
}

// fixLocalPrefixHeads replaces marked summary input heads with genuine signed
// heads over the corresponding prefix of this export. Prefix sizes never reach
// the summary itself, so the placeholder summary preimage cannot contaminate
// the prefix the head commits to.
func (b *v4ExportBuilder) fixLocalPrefixHeads() {
	if len(b.localPrefixInputs) == 0 {
		return
	}
	_, leaves, _, _ := b.leafClaims()
	for specIdx, inputs := range b.localPrefixInputs {
		sum := b.specs[specIdx].summary
		for inputIdx, size := range inputs {
			var lastSeq uint64
			for _, s := range b.specs[:size] {
				if s.entry != nil {
					lastSeq = s.entry.Sequence
				}
			}
			head := hash.TreeHead{
				Algorithm: HeadSignatureAlgorithm,
				Schema:    ExportSchemaV4,
				LogID:     hash.DeriveLogID(b.tenant),
				Index:     lastSeq,
				RootHash:  hash.MerkleRoot(leaves[:size]),
				TreeSize:  size,
				SignedAt:  b.exported.Add(-time.Minute),
			}
			head.Signature = ed25519.Sign(b.signing.priv, HeadPayload(head))
			sum.Inputs[inputIdx].Head = head
		}
	}
}

// v4SummarySpec wraps a summary leaf as a spec.
func v4SummarySpec(s *SummaryLeafViewV4) v4Spec { return v4Spec{summary: s} }

func (b *v4ExportBuilder) build() *v4Built {
	t := b.t
	t.Helper()
	b.fixLocalPrefixHeads()
	_, leaves, chains, lastEntrySeq := b.leafClaims()
	var lines []string
	for i, s := range b.specs {
		lines = append(lines, v4RenderLeaf(t, s, chains[i], leaves[i]))
	}
	head := hash.TreeHead{
		Algorithm: HeadSignatureAlgorithm,
		Schema:    ExportSchemaV4,
		LogID:     hash.DeriveLogID(b.tenant),
		Index:     lastEntrySeq,
		RootHash:  hash.MerkleRoot(leaves),
		TreeSize:  uint64(len(leaves)),
		SignedAt:  b.exported,
		PreAnchor: b.preAnchor,
	}
	if b.mutateHead != nil {
		b.mutateHead(&head)
	}
	if b.headSignature != nil {
		head.Signature = b.headSignature
	} else {
		head.Signature = ed25519.Sign(b.signing.priv, HeadPayload(head))
	}
	header := map[string]any{
		"type":           "header",
		"schema":         ExportSchemaV4,
		"log_id":         "log-" + b.tenant,
		"tenant_id":      b.tenant,
		"exported_at":    b.exported,
		"entry_count":    b.entryCount(),
		"leaf_count":     len(b.specs),
		"head":           head,
		"signing_key_id": b.signing.id,
	}
	if b.preAnchor {
		header["pre_anchor"] = true
	}
	if b.embedKey {
		header["public_key"] = hex.EncodeToString(b.signing.pub)
	}
	if b.mutateHeader != nil {
		b.mutateHeader(header)
	}
	hdr, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	out := &v4Built{text: string(hdr) + "\n" + strings.Join(lines, "\n") + "\n", head: head, leaves: leaves, chains: chains, signing: b.signing}
	for _, spec := range b.anchors {
		line, anchorHead := b.buildAnchor(spec, leaves, lastEntrySeq)
		out.text += line + "\n"
		out.anchorHeads = append(out.anchorHeads, anchorHead)
	}
	return out
}

func (b *v4ExportBuilder) entryCount() int {
	n := 0
	for _, s := range b.specs {
		if s.entry != nil {
			n++
		}
	}
	return n
}

func (b *v4ExportBuilder) buildAnchor(spec v4AnchorSpec, leaves []string, lastEntrySeq uint64) (string, hash.TreeHead) {
	t := b.t
	t.Helper()
	if spec.treeSize == 0 || spec.treeSize > uint64(len(leaves)) {
		t.Fatalf("anchor tree_size %d out of range for %d leaves", spec.treeSize, len(leaves))
	}
	// The anchor index is the last DECISION sequence inside the prefix.
	idx := uint64(0)
	count := uint64(0)
	for _, s := range b.specs {
		count++
		if count > spec.treeSize {
			break
		}
		if s.entry != nil {
			idx = s.entry.Sequence
		}
	}
	head := hash.TreeHead{
		LogID:    hash.DeriveLogID(b.tenant),
		Index:    idx,
		RootHash: hash.MerkleRoot(leaves[:spec.treeSize]),
		TreeSize: spec.treeSize,
		SignedAt: b.exported.Add(-time.Minute),
	}
	if !spec.legacy {
		head.Algorithm = HeadSignatureAlgorithm
		head.Schema = ExportSchemaV4
	}
	if spec.mutate != nil {
		spec.mutate(&head)
	}
	head.Signature = ed25519.Sign(spec.key.priv, HeadPayload(head))
	line := map[string]any{"type": "anchor", "head": head}
	if !spec.omitKeyID {
		line["key_id"] = spec.key.id
	}
	if len(spec.witnesses) > 0 {
		var witnesses []WitnessView
		for _, w := range spec.witnesses {
			witnesses = append(witnesses, WitnessView{
				WitnessID: w.id,
				PublicKey: w.key.pub,
				Signature: ed25519.Sign(w.key.priv, HeadPayload(head)),
				SignedAt:  head.SignedAt,
			})
		}
		line["witnesses"] = witnesses
	}
	raw, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), head
}

// v4RenderLeaf renders one leaf line with the computed claims filled in.
func v4RenderLeaf(t *testing.T, s v4Spec, chain, leaf string) string {
	t.Helper()
	switch {
	case s.entry != nil:
		e := *s.entry
		e.ChainHash = chain
		e.Leaf = leaf
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		m["type"] = "entry"
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	case s.receipt != nil:
		r := *s.receipt
		r.ChainHash = chain
		r.Leaf = leaf
		return string(marshalV4(t, r))
	case s.approval != nil:
		a := *s.approval
		a.ChainHash = chain
		a.Leaf = leaf
		return string(marshalV4(t, a))
	default:
		sum := *s.summary
		sum.ChainHash = chain
		sum.Leaf = leaf
		return string(marshalV4(t, sum))
	}
}

// verifyV4 runs the full reader entrypoint against a built export.
func verifyV4(t *testing.T, doc string, opts VerifyOptions) *Result {
	t.Helper()
	res := VerifyExportReaderResult(strings.NewReader(doc), nil, opts)
	if res == nil {
		t.Fatal("nil result")
	}
	return res
}

// v4Pin returns the exact HeadPin of a built head.
func v4Pin(h hash.TreeHead) *HeadPin {
	return &HeadPin{LogID: h.LogID, Index: h.Index, RootHash: h.RootHash, TreeSize: h.TreeSize}
}

// jsonUnmarshalV4 is one error-checked unmarshal for fixture surgery.
func jsonUnmarshalV4(raw []byte, v any) error { return json.Unmarshal(raw, v) }

// validSummaryLeafTypedV4 is a summary leaf with a valid envelope: the
// profile minimum body and one v4 input over a prior state of the same log.
// Summary input integrity (design section 5.3) is a later ticket; the export
// verifier parses summary leaves and enforces their envelope rules only.
func validSummaryLeafTypedV4(t *testing.T, tenant string) *SummaryLeafViewV4 {
	t.Helper()
	return &SummaryLeafViewV4{
		Type:            lineSummaryV4,
		Schema:          ExportSchemaV4,
		TenantID:        tenant,
		SummaryID:       "sum-1",
		Profile:         SummaryProfileGovernanceAuditV1,
		ProducerID:      "prod-1",
		ProducerVersion: "1.0.0",
		CreatedAt:       v4Base.Add(6 * time.Minute),
		Inputs: []SummaryInputV4{{
			InputID:  "self-prior",
			Schema:   ExportSchemaV4,
			TenantID: tenant,
			KeyID:    "ledger-k1",
			Head: hash.TreeHead{
				Algorithm: HeadSignatureAlgorithm,
				Schema:    ExportSchemaV4,
				LogID:     hash.DeriveLogID(tenant),
				Index:     1,
				RootHash:  hex64v4,
				TreeSize:  1,
				SignedAt:  v4Base,
				Signature: []byte("AAAA"),
			},
		}},
		LinkedAt: v4Base.Add(7 * time.Minute),
		Body: json.RawMessage(`{"limitations":` +
			`["input self-prior is a local prior prefix: latest_state not_checked"]}`),
	}
}
