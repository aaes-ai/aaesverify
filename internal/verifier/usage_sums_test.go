package verifier

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Wrapped uint64 arithmetic used to let crafted counts satisfy the sum and
// percentage equalities. Each report below is signed and passed before the
// checked arithmetic.
func TestUsageReportRefusesOverflowingCounts(t *testing.T) {
	priv := rfcKey(t, rfc8032Seed1, rfc8032Pub1)
	const half = uint64(1) << 63
	for _, tc := range []struct {
		name string
		edit func(*UsageReport)
		want string
	}{
		{"tenant records wrap to the decision count", func(r *UsageReport) {
			r.Tenants[0].PermitRecords, r.Tenants[0].RefusalRecords, r.Tenants[0].DeferralRecords = half, half, 3
			r.Totals.PermitRecords, r.Totals.RefusalRecords, r.Totals.DeferralRecords = half, half, 3
		}, "record counts overflow"},
		{"tenant totals wrap to zero", func(r *UsageReport) {
			second := r.Tenants[0]
			second.LogID = "aaes/log-id/1/" + strings.Repeat("f", 64)
			r.Tenants[0].ModelRecords, second.ModelRecords = half, half
			r.Tenants = append(r.Tenants, second)
			r.Totals.GovernedDecisions, r.Totals.PermitRecords, r.Totals.RefusalRecords = 6, 4, 6
			r.Capacity.TermToDate, r.Capacity.UsedPercent = 6, 6
		}, "overflow a 64-bit total"},
		{"used percent wraps", func(r *UsageReport) {
			r.Capacity.TermToDate = 1<<62 + 3
		}, "overflows the used_percent computation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := usageFixture(priv)
			tc.edit(&r)
			res := VerifyUsageReport(marshalReport(t, signUsage(t, r, priv)), UsageVerifyOptions{})
			if res.OK || !strings.Contains(strings.Join(res.Errors, "\n"), tc.want) {
				t.Fatalf("errors %q, want one containing %q", res.Errors, tc.want)
			}
		})
	}
}

func TestCheckedSumDetectsCarry(t *testing.T) {
	if got, ok := checkedSum(1, 2, 3); !ok || got != 6 {
		t.Fatalf("checkedSum(1,2,3) = %d %v", got, ok)
	}
	if _, ok := checkedSum(^uint64(0), 1); ok {
		t.Fatal("a carry out of 64 bits was not reported")
	}
}

// A usage report member repeated exactly or under case folding is refused:
// Go would keep the last spelling while other readers show the first.
func TestUsageReportRefusesRepeatedMembers(t *testing.T) {
	priv := rfcKey(t, rfc8032Seed1, rfc8032Pub1)
	raw := marshalReport(t, signUsage(t, usageFixture(priv), priv))
	for _, tc := range []struct{ old, new string }{
		{`"deployment_id":"dep_test"`, `"deployment_id":"dep_other","Deployment_ID":"dep_test"`},
		{`"deployment_id":"dep_test"`, `"deployment_id":"dep_test","deployment_id":"dep_test"`},
		{`"governed_decisions":3`, `"governed_decisions":3,"Governed_Decisions":3`},
	} {
		edited := bytes.Replace(raw, []byte(tc.old), []byte(tc.new), 1)
		if bytes.Equal(edited, raw) {
			t.Fatalf("fixture lacks %s", tc.old)
		}
		if _, err := ParseUsageReport(edited); !errors.Is(err, ErrUsageReport) || !strings.Contains(err.Error(), "duplicate object key") {
			t.Fatalf("%s: err = %v", tc.new, err)
		}
		if res := VerifyUsageReport(edited, UsageVerifyOptions{}); res.OK {
			t.Fatalf("%s verified", tc.new)
		}
	}
}
