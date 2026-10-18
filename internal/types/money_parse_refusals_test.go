package types

import (
	"math"
	"strings"
	"testing"
)

func TestMoneyConstructorsRefuseBadInput(t *testing.T) {
	if _, err := NewMoney(1, "no"); err == nil || !strings.Contains(err.Error(), "currency") {
		t.Fatalf("NewMoney bad currency = %v", err)
	}
	// Non-finite input is never a permissive maximum: it becomes a negative
	// amount every validator refuses. Finite out-of-range input saturates with
	// its sign instead of relying on the platform's float-to-int conversion.
	for _, c := range []struct {
		major float64
		want  int64
	}{
		{math.NaN(), math.MinInt64},
		{math.Inf(1), math.MinInt64},
		{math.Inf(-1), math.MinInt64},
		{1e17, math.MaxInt64},
		{1e307, math.MaxInt64},
		{-1e17, math.MinInt64},
		{-1e307, math.MinInt64},
		{-92233720368547758.08, math.MinInt64},
		{1.5, 150},
	} {
		if m := USDM(c.major); m.Minor != c.want || m.Currency != DefaultCurrency {
			t.Fatalf("USDM(%v) = %+v, want minor %d", c.major, m, c.want)
		}
	}
	if _, err := ParseMajor("1.00", "no"); err == nil || !strings.Contains(err.Error(), "currency") {
		t.Fatalf("ParseMajor bad currency = %v", err)
	}
	if _, err := ParseMajor("1.999", "USD"); err == nil || !strings.Contains(err.Error(), "fraction digits") {
		t.Fatalf("ParseMajor excess fraction = %v", err)
	}
	if _, err := ParseMajor("99999999999999999999.00", "USD"); err == nil || !strings.Contains(err.Error(), "overflows") {
		t.Fatalf("ParseMajor whole overflow = %v", err)
	}
	a, _ := NewMoney(5, "USD")
	b, _ := NewMoney(5, "USD")
	if cmp, err := a.Cmp(b); err != nil || cmp != 0 {
		t.Fatalf("Cmp equal = %d, %v", cmp, err)
	}
	if _, ok := (Money{Minor: 100, Currency: "EUR"}).USDMajor(); ok {
		t.Fatal("USDMajor must refuse a non-USD currency")
	}
	if v, ok := (Money{Minor: 250, Currency: ""}).USDMajor(); !ok || v != 2.5 {
		t.Fatalf("USDMajor empty currency = %v, %v", v, ok)
	}
	if v, ok := (Money{Minor: 250, Currency: "USD"}).USDMajor(); !ok || v != 2.5 {
		t.Fatalf("USDMajor USD = %v, %v", v, ok)
	}
}

func TestMoneySameCurrencyAndParseMajorEdges(t *testing.T) {
	a, _ := NewMoney(1, "USD")
	b, _ := NewMoney(2, "USD")
	if !a.SameCurrency(b) {
		t.Fatal("SameCurrency USD/USD")
	}
	if a.SameCurrency(Money{}) {
		t.Fatal("SameCurrency with unstated must be false")
	}
	if _, err := currencyOf(a, Money{Minor: 1, Currency: "EUR"}); err == nil || !strings.Contains(err.Error(), "currency") {
		t.Fatalf("currencyOf mismatch = %v", err)
	}
	if _, err := ParseMajor("1.", "USD"); err == nil || !strings.Contains(err.Error(), "plain decimal") {
		t.Fatalf("trailing decimal = %v", err)
	}
	if _, err := ParseMajor(".5", "USD"); err == nil || !strings.Contains(err.Error(), "plain decimal") {
		t.Fatalf("leading decimal = %v", err)
	}
	if _, err := ParseMajor("1.2.3", "USD"); err == nil || !strings.Contains(err.Error(), "plain decimal") {
		t.Fatalf("two dots = %v", err)
	}
	if _, err := ParseMajor("-1.00", "USD"); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("negative = %v", err)
	}
}

func TestParseMajorOverflowAndSplitEdges(t *testing.T) {
	// Too many fraction digits for KWD (exponent 3) is refused before any
	// integer conversion of the fraction.
	hugeFrac := "1." + strings.Repeat("9", 20)
	if _, err := ParseMajor(hugeFrac, "KWD"); err == nil || !strings.Contains(err.Error(), "fraction digits") {
		t.Fatalf("excess KWD fraction = %v", err)
	}
	if _, err := ParseMajor("", "USD"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty amount = %v", err)
	}
	if _, err := ParseMajor("+1.00", "USD"); err == nil || !strings.Contains(err.Error(), "plain decimal") {
		t.Fatalf("leading plus = %v", err)
	}
	a, _ := NewMoney(1, "USD")
	if c, err := currencyOf(a, Money{}); err != nil || c != "USD" {
		t.Fatalf("currencyOf stated+empty = %q, %v", c, err)
	}
}
