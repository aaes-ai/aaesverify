package types

import "testing"

func TestFourDecimalMoneyISO4217(t *testing.T) {
	// ISO 4217 maintenance agency SIX List One, published 2026-09-17:
	// CLF and UYW have exponent 4; ISK remains exponent 0.
	for currency, want := range map[string]int{"CLF": 4, "UYW": 4, "clf": 4, " uyw ": 4, "ISK": 0, "ZZZ": 2} {
		if got := CurrencyExponent(currency); got != want {
			t.Fatalf("CurrencyExponent(%q) = %d, want %d", currency, got, want)
		}
	}
	for _, currency := range []string{"CLF", "UYW"} {
		t.Run(currency, func(t *testing.T) {
			for raw, want := range map[string]int64{"1": 10000, "1.0000": 10000, "1.2345": 12345, "0.001": 10, "0.0001": 1, "0": 0, "922337203685477.5807": 9223372036854775807} {
				got, err := ParseMajor(raw, currency)
				if err != nil || got != (Money{Minor: want, Currency: currency}) {
					t.Fatalf("ParseMajor(%q, %q) = %+v, %v; want minor %d", raw, currency, got, err, want)
				}
				roundTrip, err := ParseMajor(got.Major(), currency)
				if err != nil || roundTrip != got {
					t.Fatalf("round trip %q = %+v, %v; want %+v", got.Major(), roundTrip, err, got)
				}
			}
			for _, raw := range []string{"1.00001", "922337203685477.5808", "922337203685478"} {
				if _, err := ParseMajor(raw, currency); err == nil {
					t.Fatalf("ParseMajor(%q, %q) must refuse excess precision or overflow", raw, currency)
				}
			}
			for minor, want := range map[int64]string{10000: "1.0000", 12345: "1.2345", 1: "0.0001", -1: "-0.0001"} {
				if got := (Money{Minor: minor, Currency: currency}).String(); got != currency+" "+want {
					t.Fatalf("format %d %s = %q, want %q", minor, currency, got, currency+" "+want)
				}
			}
		})
	}
}

func TestIndexedPesoISO4217(t *testing.T) {
	if CurrencyExponent("UYI") != 0 {
		t.Fatal("UYI has ISO 4217 exponent 0")
	}
	for raw, minor := range map[string]int64{"1": 1, "123": 123, "0": 0, "9223372036854775807": 9223372036854775807} {
		got, err := ParseMajor(raw, "UYI")
		if err != nil || got.Minor != minor || got.Currency != "UYI" {
			t.Fatalf("ParseMajor(%q, UYI) = %+v, %v", raw, got, err)
		}
		if got.String() != "UYI "+raw {
			t.Fatalf("format = %q, want UYI %s", got.String(), raw)
		}
	}
	for _, raw := range []string{"1.5", "1.00", "-1", "9223372036854775808"} {
		if _, err := ParseMajor(raw, "UYI"); err == nil {
			t.Fatalf("ParseMajor(%q, UYI) must refuse", raw)
		}
	}
}
