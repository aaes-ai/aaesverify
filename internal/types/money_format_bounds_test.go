package types

import (
	"math"
	"testing"
)

func TestMoneyFormattingSignedBounds(t *testing.T) {
	cases := []struct {
		currency string
		minor    int64
		want     string
	}{
		{"JPY", math.MinInt64, "-9223372036854775808"},
		{"USD", math.MinInt64, "-92233720368547758.08"},
		{"KWD", math.MinInt64, "-9223372036854775.808"},
		{"CLF", math.MinInt64, "-922337203685477.5808"},
		{"USD", math.MinInt64 + 1, "-92233720368547758.07"},
		{"KWD", math.MinInt64 + 1, "-9223372036854775.807"},
		{"CLF", math.MinInt64 + 1, "-922337203685477.5807"},
		{"JPY", math.MaxInt64, "9223372036854775807"},
		{"USD", math.MaxInt64, "92233720368547758.07"},
		{"KWD", math.MaxInt64, "9223372036854775.807"},
		{"CLF", math.MaxInt64, "922337203685477.5807"},
		{"USD", -1, "-0.01"},
		{"KWD", -1, "-0.001"},
		{"CLF", -1, "-0.0001"},
		{"USD", 0, "0.00"},
		{"KWD", 0, "0.000"},
		{"CLF", 0, "0.0000"},
		{"USD", 1, "0.01"},
		{"KWD", 1, "0.001"},
		{"CLF", 1, "0.0001"},
	}
	for _, tc := range cases {
		m := Money{Minor: tc.minor, Currency: tc.currency}
		if got := m.Major(); got != tc.want {
			t.Errorf("%s %d Major()=%q, want %q", tc.currency, tc.minor, got, tc.want)
		}
		if got := m.String(); got != tc.currency+" "+tc.want {
			t.Errorf("%s %d String()=%q", tc.currency, tc.minor, got)
		}
		if tc.minor == math.MinInt64 {
			diff, err := (Money{Minor: -1, Currency: tc.currency}).Sub(Money{Minor: math.MaxInt64, Currency: tc.currency})
			if err != nil || diff != m {
				t.Errorf("representable subtraction=%+v, %v; want %+v", diff, err, m)
			}
		}
	}
	if got := (Money{Minor: math.MinInt64}).Major(); got != "-9223372036854775808 minor units (currency not stated)" {
		t.Errorf("unstated=%q", got)
	}
}
