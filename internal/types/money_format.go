package types

import "fmt"

// Major renders the amount in major units for human-facing text, with the
// currency's own number of decimal places: 1234 USD minor renders "12.34",
// 1234 JPY minor renders "1234", 1234 KWD minor renders "1.234". An amount
// with no currency renders the raw minor-unit count with a marker, so a
// reader is never shown a figure that looks like money but names no unit.
func (m Money) Major() string {
	if m.Currency == "" {
		return fmt.Sprintf("%d minor units (currency not stated)", m.Minor)
	}
	exp := CurrencyExponent(m.Currency)
	if exp == 0 {
		return fmt.Sprintf("%d", m.Minor)
	}
	scale := int64(1)
	for i := 0; i < exp; i++ {
		scale *= 10
	}
	sign := ""
	minor := uint64(m.Minor)
	if m.Minor < 0 {
		sign = "-"
		// Add one before negation so MinInt64 has an exact unsigned magnitude.
		minor = uint64(-(m.Minor + 1)) + 1
	}
	return fmt.Sprintf("%s%d.%0*d", sign, minor/uint64(scale), exp, minor%uint64(scale))
}

// String renders the amount with its currency code, e.g. "USD 12.34".
func (m Money) String() string {
	if m.Currency == "" {
		return m.Major()
	}
	return m.Currency + " " + m.Major()
}
