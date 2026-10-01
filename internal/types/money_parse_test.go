package types

import (
	"strings"
	"testing"
)

func TestParseMajor(t *testing.T) {
	cases := []struct {
		raw, currency string
		wantMinor     int64
		ok            bool
	}{
		{"12.50", "USD", 1250, true},
		{"12.5", "JPY", 0, false},
		{"1.234", "KWD", 1234, true},
		{"-1", "USD", 0, false},
		{"1e3", "USD", 0, false},
		{"1E3", "EUR", 0, false},
		{"0", "USD", 0, true},
		{"12", "JPY", 12, true},
		{"12.345", "USD", 0, false},
		{"  12.50  ", "usd", 1250, true},
		{"12.", "USD", 0, false},
		{".5", "USD", 0, false},
	}
	for _, tc := range cases {
		got, err := ParseMajor(tc.raw, tc.currency)
		if tc.ok {
			if err != nil {
				t.Fatalf("ParseMajor(%q, %q) unexpected error: %v", tc.raw, tc.currency, err)
			}
			wantCur, _ := NormalizeCurrency(tc.currency)
			if got.Minor != tc.wantMinor || got.Currency != wantCur {
				t.Fatalf("ParseMajor(%q, %q) = %+v, want minor=%d currency=%s", tc.raw, tc.currency, got, tc.wantMinor, wantCur)
			}
			continue
		}
		if err == nil {
			t.Fatalf("ParseMajor(%q, %q) = %+v, want error", tc.raw, tc.currency, got)
		}
	}
}

func TestParseMajorOverflowRefused(t *testing.T) {
	_, err := ParseMajor("92233720368547758.08", "USD")
	if err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("overflow: %v", err)
	}
}
