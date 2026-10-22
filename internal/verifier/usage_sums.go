package verifier

import (
	"errors"
	"math/bits"
)

// The usage report's internal sums. A report is signed by the deployment's
// own usage key, the party that benefits from under-reporting, so these
// checks are its only internal consistency guard. Every sum and product is
// checked for uint64 overflow: wrapped arithmetic would let crafted counts
// satisfy an equality they do not meet.

// checkedSum adds values and reports whether the total overflowed.
func checkedSum(values ...uint64) (uint64, bool) {
	var total, carry uint64
	for _, v := range values {
		total, carry = bits.Add64(total, v, 0)
		if carry != 0 {
			return 0, false
		}
	}
	return total, true
}

// addTotals adds one tenant's counts to sum and reports any overflow.
func addTotals(sum *UsageTotals, t UsageTenant) bool {
	var ok [5]bool
	sum.GovernedDecisions, ok[0] = checkedSum(sum.GovernedDecisions, t.GovernedDecisions)
	sum.PermitRecords, ok[1] = checkedSum(sum.PermitRecords, t.PermitRecords)
	sum.RefusalRecords, ok[2] = checkedSum(sum.RefusalRecords, t.RefusalRecords)
	sum.DeferralRecords, ok[3] = checkedSum(sum.DeferralRecords, t.DeferralRecords)
	sum.ModelRecords, ok[4] = checkedSum(sum.ModelRecords, t.ModelRecords)
	return ok == [5]bool{true, true, true, true, true}
}

func verifyUsageSums(r UsageReport) error {
	var sum UsageTotals
	var errs []error
	for _, t := range r.Tenants {
		if !addTotals(&sum, t) {
			return usageErr("tenant counts overflow a 64-bit total")
		}
		records, ok := checkedSum(t.PermitRecords, t.RefusalRecords, t.DeferralRecords)
		if !ok {
			return usageErr("tenant %s record counts overflow a 64-bit total", t.LogID)
		}
		if t.GovernedDecisions > records || (records > 0 && t.GovernedDecisions == 0) {
			errs = append(errs, usageErr("tenant %s counts %d decisions from %d records", t.LogID, t.GovernedDecisions, records))
		}
		if records > 0 && (t.FirstSequence == 0 || t.FirstSequence > t.LastSequence) {
			errs = append(errs, usageErr("tenant %s sequence range %d..%d", t.LogID, t.FirstSequence, t.LastSequence))
		}
	}
	if sum != r.Totals {
		errs = append(errs, usageErr("totals %+v are not the sum of the tenants %+v", r.Totals, sum))
	}
	if r.Capacity != nil {
		errs = append(errs, verifyUsageCapacity(r, *r.Capacity)...)
	}
	return errors.Join(errs...)
}

func verifyUsageCapacity(r UsageReport, c UsageCapacity) []error {
	var errs []error
	inTerm := !r.Period.Start.Before(c.TermStart) && !r.Period.End.After(c.TermEnd)
	hi, scaled := bits.Mul64(c.TermToDate, 100)
	switch {
	case c.Pool != UsagePoolLicenseTerm || !c.TermStart.Before(c.TermEnd) || c.GovernedDecisions == 0:
		errs = append(errs, usageErr("capacity names no license term pool"))
	case hi != 0:
		errs = append(errs, usageErr("term_to_date %d overflows the used_percent computation", c.TermToDate))
	case c.UsedPercent != scaled/c.GovernedDecisions:
		errs = append(errs, usageErr("used_percent %d is not term_to_date over the pool", c.UsedPercent))
	case inTerm && c.TermToDate < r.Totals.GovernedDecisions:
		errs = append(errs, usageErr("term_to_date %d is below the period's own count %d", c.TermToDate, r.Totals.GovernedDecisions))
	case c.ProjectedTermTotal != nil && *c.ProjectedTermTotal < c.TermToDate:
		errs = append(errs, usageErr("projection %d is below term_to_date %d", *c.ProjectedTermTotal, c.TermToDate))
	}
	wantWarnings := UsageWarningsActive
	if r.Environment == EnvironmentNonProduction {
		wantWarnings = UsageWarningsSuppressed
	}
	if c.Warnings != wantWarnings {
		errs = append(errs, usageErr("warnings %q for a %s environment", c.Warnings, r.Environment))
	}
	return errs
}
