package verifier

import (
	"encoding/json"
	"fmt"
)

// The minimum body contract of design section 5.2. The envelope covers every
// body byte cryptographically regardless of profile; the frozen minimum
// shape — findings, metrics, and the required limitations array — applies to
// SummaryProfileGovernanceAuditV1, the one profile the reservation freezes.
// Additional members in the body, a finding, or a metric value belong to the
// profile and are allowed here; duplicate member names and nulls were already
// refused by the token walk, which descends into body like anywhere else.

// summaryBodyV4Probe decodes the profile-owned body without closing it:
// plain decoding (unknown members allowed), pointer fields so a missing
// member is distinguishable from a present one.
type summaryBodyV4Probe struct {
	Findings    *[]json.RawMessage          `json:"findings"`
	Metrics     *map[string]json.RawMessage `json:"metrics"`
	Limitations *[]string                   `json:"limitations"`
}

// summaryFindingV4 is the minimum finding shape: a nonempty code and a
// nonempty input_ids array. detail and further members are profile-owned.
type summaryFindingV4 struct {
	Code     *string   `json:"code"`
	InputIDs *[]string `json:"input_ids"`
}

// summaryMetricV4 is the minimum metric-value shape: a JSON-number value and
// a nonempty input_ids array.
type summaryMetricV4 struct {
	Value    *json.Number `json:"value"`
	InputIDs *[]string    `json:"input_ids"`
}

// validateBodyV4 enforces that body is a JSON object, and — for the frozen
// governance-audit profile — the section 5.2 minimum contract, including
// that every input_ids member names an item of the outer inputs array: the
// typed input list is the exhaustive set of export states findings and
// metrics may draw on.
func (l *SummaryLeafViewV4) validateBodyV4() error {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(l.Body, &probe); err != nil || probe == nil {
		return fmt.Errorf("%w: summary body must be a JSON object", ErrMalformed)
	}
	if l.Profile != SummaryProfileGovernanceAuditV1 {
		// An unknown profile is covered cryptographically but uninterpreted;
		// a profile-aware consumer refuses it before relying on it.
		return nil
	}
	var body summaryBodyV4Probe
	if err := checkTypedJSONAliases(l.Body, &body); err != nil {
		return fmt.Errorf("%w: summary body: %v", ErrMalformed, err)
	}
	if err := json.Unmarshal(l.Body, &body); err != nil {
		return fmt.Errorf("%w: summary body: %v", ErrMalformed, err)
	}
	if body.Limitations == nil {
		return fmt.Errorf("%w: body.limitations is a required array of strings", ErrMalformed)
	}
	l.limitationsParsed = true
	l.parsedLimitations = append([]string(nil), (*body.Limitations)...)
	known := make(map[string]struct{}, len(l.Inputs))
	for _, in := range l.Inputs {
		known[in.InputID] = struct{}{}
	}
	if body.Findings != nil {
		for i, raw := range *body.Findings {
			if err := validateFindingV4(raw, known); err != nil {
				return fmt.Errorf("%w (finding %d)", err, i)
			}
		}
	}
	if body.Metrics != nil {
		for name, raw := range *body.Metrics {
			if err := validateMetricV4(raw, known); err != nil {
				return fmt.Errorf("%w (metric %q)", err, name)
			}
		}
	}
	return nil
}

// validateFindingV4 enforces the minimum finding shape and resolves its
// evidence references against the outer input list.
func validateFindingV4(raw json.RawMessage, known map[string]struct{}) error {
	var f summaryFindingV4
	if err := checkTypedJSONAliases(raw, &f); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("%w: finding must be an object: %v", ErrMalformed, err)
	}
	if f.Code == nil || *f.Code == "" {
		return fmt.Errorf("%w: finding.code is required and nonempty", ErrMalformed)
	}
	return validateInputIDsV4(f.InputIDs, known)
}

// validateMetricV4 enforces the minimum metric shape and resolves its
// evidence references against the outer input list.
func validateMetricV4(raw json.RawMessage, known map[string]struct{}) error {
	var m summaryMetricV4
	if err := checkTypedJSONAliases(raw, &m); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("%w: metric value must be an object: %v", ErrMalformed, err)
	}
	if m.Value == nil {
		return fmt.Errorf("%w: metric.value is a required JSON number", ErrMalformed)
	}
	return validateInputIDsV4(m.InputIDs, known)
}

// validateInputIDsV4 requires a nonempty input_ids array whose every member
// names an item of the outer inputs array.
func validateInputIDsV4(ids *[]string, known map[string]struct{}) error {
	if ids == nil || len(*ids) == 0 {
		return fmt.Errorf("%w: input_ids is a required nonempty array", ErrMalformed)
	}
	for _, id := range *ids {
		if _, ok := known[id]; !ok {
			return fmt.Errorf("%w: input_ids member %q names no item of the outer inputs array", ErrMalformed, id)
		}
	}
	return nil
}
