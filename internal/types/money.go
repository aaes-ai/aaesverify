package types

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Money is an amount of money: integer minor units of one ISO 4217 currency.
//
// AAES never stores or sums money as a float. A float cannot represent most
// decimal fractions exactly, and a budget that drifts by a rounding error is a
// budget whose bound nobody can state. Minor is the count of the currency's
// smallest unit (cents for USD, yen for JPY, millimes for TND); Currency is
// the uppercase three-letter ISO 4217 code.
//
// AAES performs NO currency conversion, ever. A task budget is denominated in
// one currency, an action's declared amount carries its own currency, and an
// amount in a different currency than the bound it is checked against is a
// REFUSAL (ErrCurrencyMismatch), not a conversion. There is no exchange-rate
// table anywhere in this codebase on purpose: a rate AAES cannot verify is a
// number AAES will not print.
type Money struct {
	// Minor is the amount in the currency's minor units. It may be negative
	// only in transient arithmetic; a budget, a committed total and a declared
	// amount are validated non-negative at the edges.
	Minor int64 `json:"minor"`
	// Currency is the ISO 4217 code, uppercase. Empty means no amount was
	// stated at all: the zero Money is "no money", which is not the same fact
	// as a zero amount of a named currency.
	Currency string `json:"currency,omitempty"`
}

// DefaultCurrency is the denomination applied when a deployment creates a
// task budget without naming one. Deployments that ran before money was
// multi-currency denominated everything in USD, so USD stays the default and
// existing flows remain ergonomic — but the currency is always stored and
// reported explicitly, never assumed downstream of creation.
const DefaultCurrency = "USD"

// ErrCurrencyMismatch is the typed refusal for an amount presented in a
// different currency than the bound it is checked against. AAES does not
// convert; it refuses.
var ErrCurrencyMismatch = errors.New("types: currency mismatch and AAES does not perform currency conversion")

// ErrMoneyOverflow refuses arithmetic outside the signed minor-unit range.
var ErrMoneyOverflow = errors.New("types: money arithmetic overflows int64")

// zeroDecimalCurrencies are the ISO 4217 currencies whose minor unit exponent
// is 0: the minor unit IS the unit.
var zeroDecimalCurrencies = map[string]bool{
	"BIF": true, "CLP": true, "DJF": true, "GNF": true, "ISK": true,
	"JPY": true, "KMF": true, "KRW": true, "PYG": true, "RWF": true,
	"UGX": true, "UYI": true, "VND": true, "VUV": true,
	"XAF": true, "XOF": true, "XPF": true,
}

// threeDecimalCurrencies are the ISO 4217 currencies whose minor unit exponent
// is 3.
var threeDecimalCurrencies = map[string]bool{
	"BHD": true, "IQD": true, "JOD": true, "KWD": true,
	"LYD": true, "OMR": true, "TND": true,
}

// fourDecimalCurrencies are the ISO 4217 fund units whose exponent is 4.
// SIX List One (2026-09-17) records CLF and UYW with four decimal places.
var fourDecimalCurrencies = map[string]bool{"CLF": true, "UYW": true}

// CurrencyExponent returns the ISO 4217 minor-unit exponent for a currency:
// how many decimal places sit between the major unit and the minor unit. The
// safe default is 2, the exponent of the overwhelming majority of currencies;
// an unknown code therefore still formats and parses, just with two places.
func CurrencyExponent(currency string) int {
	switch c := strings.ToUpper(strings.TrimSpace(currency)); {
	case zeroDecimalCurrencies[c]:
		return 0
	case threeDecimalCurrencies[c]:
		return 3
	case fourDecimalCurrencies[c]:
		return 4
	default:
		return 2
	}
}

// NormalizeCurrency validates and canonicalises an ISO 4217 code: trimmed and
// uppercased, exactly three ASCII letters. It fails closed: a malformed code
// is an error, never a guess.
func NormalizeCurrency(raw string) (string, error) {
	c := strings.ToUpper(strings.TrimSpace(raw))
	if len(c) != 3 {
		return "", fmt.Errorf("types: currency %q is not a three-letter ISO 4217 code", raw)
	}
	for _, r := range c {
		if r < 'A' || r > 'Z' {
			return "", fmt.Errorf("types: currency %q is not a three-letter ISO 4217 code", raw)
		}
	}
	return c, nil
}

// NewMoney builds a Money, validating and normalising the currency.
func NewMoney(minor int64, currency string) (Money, error) {
	c, err := NormalizeCurrency(currency)
	if err != nil {
		return Money{}, err
	}
	return Money{Minor: minor, Currency: c}, nil
}

// USDM is a convenience constructor for amounts stated in whole or fractional
// MAJOR USD units — test literals and configuration written the way a human
// writes dollars. The value is converted to integer minor units immediately
// (rounded half away from zero); nothing is ever STORED as a float.
func USDM(major float64) Money {
	if math.IsNaN(major) || math.IsInf(major, 0) {
		return Money{Minor: math.MaxInt64, Currency: DefaultCurrency}
	}
	return Money{Minor: int64(math.Round(major * 100)), Currency: DefaultCurrency}
}

// ParseMajor parses a human-typed major-unit decimal into Money for currency.
// It accepts only plain decimals with at most CurrencyExponent fraction digits.
// Negatives, exponent notation and overflow are refused.
func ParseMajor(raw, currency string) (Money, error) {
	c, err := NormalizeCurrency(currency)
	if err != nil {
		return Money{}, err
	}
	whole, frac, err := splitMajorDecimal(raw)
	if err != nil {
		return Money{}, err
	}
	exp := CurrencyExponent(c)
	if len(frac) > exp {
		return Money{}, fmt.Errorf("types: amount %q has more than %d fraction digits for %s", raw, exp, c)
	}
	for len(frac) < exp {
		frac += "0"
	}
	scale := int64(1)
	for i := 0; i < exp; i++ {
		scale *= 10
	}
	w, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return Money{}, fmt.Errorf("types: amount %q overflows", raw)
	}
	// frac is only decimal digits and at most CurrencyExponent long after the
	// length check and zero-pad above, so it always fits in int64.
	var f int64
	for i := 0; i < len(frac); i++ {
		f = f*10 + int64(frac[i]-'0')
	}
	if scale > 0 && w > (math.MaxInt64-f)/scale {
		return Money{}, fmt.Errorf("types: amount %q overflows", raw)
	}
	return Money{Minor: w*scale + f, Currency: c}, nil
}

func splitMajorDecimal(raw string) (whole, frac string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", fmt.Errorf("types: amount is empty")
	}
	if s[0] == '-' {
		return "", "", fmt.Errorf("types: amount must not be negative")
	}
	if s[0] == '+' {
		return "", "", fmt.Errorf("types: amount %q is not a plain decimal", raw)
	}
	for _, r := range s {
		if r == '.' {
			continue
		}
		if r < '0' || r > '9' {
			return "", "", fmt.Errorf("types: amount %q is not a plain decimal", raw)
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) > 2 {
		return "", "", fmt.Errorf("types: amount %q is not a plain decimal", raw)
	}
	whole = parts[0]
	if len(parts) == 2 {
		frac = parts[1]
		// A bare trailing or leading decimal point is not a plain decimal.
		if whole == "" || frac == "" {
			return "", "", fmt.Errorf("types: amount %q is not a plain decimal", raw)
		}
	}
	return whole, frac, nil
}

// Validate checks that a stated amount is well-formed: a valid currency, and
// currency present whenever a nonzero amount is. The zero Money ("no money
// stated") is valid; a nonzero amount with no currency is not, because an
// amount whose unit nobody named is not an amount anyone can bound.
func (m Money) Validate() error {
	if m.Currency == "" {
		if m.Minor != 0 {
			return fmt.Errorf("types: amount of %d minor units names no currency", m.Minor)
		}
		return nil
	}
	c, err := NormalizeCurrency(m.Currency)
	if err != nil {
		return err
	}
	if c != m.Currency {
		return fmt.Errorf("types: currency %q must be the uppercase ISO 4217 code %q", m.Currency, c)
	}
	return nil
}

// IsZero reports whether no amount is stated.
func (m Money) IsZero() bool { return m.Minor == 0 && m.Currency == "" }

// SameCurrency reports whether two amounts share a denomination. Two "no
// money" zero values share one; a zero value and a stated amount do not.
func (m Money) SameCurrency(o Money) bool { return m.Currency == o.Currency }

// currencyOf resolves the denomination of an operation between two amounts:
// the stated one when only one is stated, the shared one when both are. A
// stated currency on both sides that disagrees is the mismatch the caller
// must refuse on.
func currencyOf(a, b Money) (string, error) {
	switch {
	case a.Currency == "":
		return b.Currency, nil
	case b.Currency == "":
		return a.Currency, nil
	case a.Currency == b.Currency:
		return a.Currency, nil
	default:
		return "", fmt.Errorf("%w: %s against %s", ErrCurrencyMismatch, a.Currency, b.Currency)
	}
}

// Add sums two amounts of one currency. A currency mismatch is an error: AAES
// never converts, so it cannot add. Overflow returns ErrMoneyOverflow.
func (m Money) Add(o Money) (Money, error) {
	c, err := currencyOf(m, o)
	if err != nil {
		return Money{}, err
	}
	if o.Minor > 0 && m.Minor > math.MaxInt64-o.Minor || o.Minor < 0 && m.Minor < math.MinInt64-o.Minor {
		return Money{}, ErrMoneyOverflow
	}
	return Money{Minor: m.Minor + o.Minor, Currency: c}, nil
}

// Sub subtracts o from m, using the currency and overflow rules of Add.
func (m Money) Sub(o Money) (Money, error) {
	c, err := currencyOf(m, o)
	if err != nil {
		return Money{}, err
	}
	if o.Minor > 0 && m.Minor < math.MinInt64+o.Minor || o.Minor < 0 && m.Minor > math.MaxInt64+o.Minor {
		return Money{}, ErrMoneyOverflow
	}
	return Money{Minor: m.Minor - o.Minor, Currency: c}, nil
}

// Cmp compares two amounts of one currency: -1, 0 or 1. A currency mismatch
// is an error: AAES never converts, so it cannot compare.
func (m Money) Cmp(o Money) (int, error) {
	if _, err := currencyOf(m, o); err != nil {
		return 0, err
	}
	switch {
	case m.Minor < o.Minor:
		return -1, nil
	case m.Minor > o.Minor:
		return 1, nil
	default:
		return 0, nil
	}
}

// USDMajor returns the amount in major USD units for writing back to an
// operator-authored *_usd float config field. It returns false when Currency
// is set and is not USD: AAES never converts, so a non-USD amount cannot be
// spelled as a USD major float. An empty currency (no amount stated) yields
// 0, true so a blank ceiling can round-trip.
func (m Money) USDMajor() (float64, bool) {
	if m.Currency != "" && m.Currency != DefaultCurrency {
		return 0, false
	}
	return float64(m.Minor) / 100, true
}
