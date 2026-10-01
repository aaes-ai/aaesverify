package types

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeCurrency(t *testing.T) {
	c, err := NormalizeCurrency(" eur ")
	if err != nil || c != "EUR" {
		t.Fatalf("NormalizeCurrency(\" eur \") = %q, %v; want EUR, nil", c, err)
	}
	for _, bad := range []string{"", "US", "USDD", "U1D", "us$"} {
		if _, err := NormalizeCurrency(bad); err == nil {
			t.Fatalf("NormalizeCurrency(%q) succeeded; want refusal", bad)
		}
	}
}

func TestCurrencyExponent(t *testing.T) {
	cases := map[string]int{"USD": 2, "EUR": 2, "JPY": 0, "KRW": 0, "KWD": 3, "TND": 3, "ZZZ": 2}
	for currency, want := range cases {
		if got := CurrencyExponent(currency); got != want {
			t.Fatalf("CurrencyExponent(%q) = %d, want %d", currency, got, want)
		}
	}
}

func TestMoneyArithmeticSameCurrency(t *testing.T) {
	a, _ := NewMoney(10000, "USD")
	b, _ := NewMoney(250, "USD")
	sum, err := a.Add(b)
	if err != nil || sum.Minor != 10250 || sum.Currency != "USD" {
		t.Fatalf("Add = %v, %v", sum, err)
	}
	diff, err := a.Sub(b)
	if err != nil || diff.Minor != 9750 {
		t.Fatalf("Sub = %v, %v", diff, err)
	}
	if cmp, err := a.Cmp(b); err != nil || cmp != 1 {
		t.Fatalf("Cmp = %d, %v", cmp, err)
	}
}

func TestMoneyArithmeticNoFloatDrift(t *testing.T) {
	// 0.1 + 0.2 in float64 is famously not 0.3. In minor units it is exact.
	a := USDM(0.1)
	b := USDM(0.2)
	sum, err := a.Add(b)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Minor != 30 {
		t.Fatalf("0.1 + 0.2 = %d minor units, want exactly 30", sum.Minor)
	}
	// Repeated addition stays exact where floats accumulate error.
	total := Money{Currency: "USD"}
	for i := 0; i < 1000; i++ {
		total, err = total.Add(USDM(0.01))
		if err != nil {
			t.Fatal(err)
		}
	}
	if total.Minor != 1000 {
		t.Fatalf("1000 x USD 0.01 = %d minor units, want exactly 1000", total.Minor)
	}
}

func TestMoneyCrossCurrencyRefused(t *testing.T) {
	usd, _ := NewMoney(100, "USD")
	eur, _ := NewMoney(100, "EUR")
	if _, err := usd.Add(eur); !errors.Is(err, ErrCurrencyMismatch) {
		t.Fatalf("USD+EUR err = %v, want ErrCurrencyMismatch", err)
	}
	if _, err := usd.Sub(eur); !errors.Is(err, ErrCurrencyMismatch) {
		t.Fatalf("USD-EUR err = %v, want ErrCurrencyMismatch", err)
	}
	if _, err := usd.Cmp(eur); !errors.Is(err, ErrCurrencyMismatch) {
		t.Fatalf("USD vs EUR err = %v, want ErrCurrencyMismatch", err)
	}
}

func TestMoneyZeroValueIsUnstated(t *testing.T) {
	var m Money
	if !m.IsZero() {
		t.Fatal("zero Money should report IsZero")
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("zero Money should validate: %v", err)
	}
	// A zero value adds to a stated amount and takes its currency.
	usd, _ := NewMoney(5, "USD")
	sum, err := m.Add(usd)
	if err != nil || sum.Currency != "USD" || sum.Minor != 5 {
		t.Fatalf("zero + USD 0.05 = %v, %v", sum, err)
	}
	// A nonzero amount with no currency is invalid.
	if err := (Money{Minor: 1}).Validate(); err == nil {
		t.Fatal("nonzero amount with no currency must be invalid")
	}
}

func TestMoneyValidateNormalisation(t *testing.T) {
	if err := (Money{Minor: 1, Currency: "usd"}).Validate(); err == nil {
		t.Fatal("lowercase currency must be invalid (normalise at the edge, store uppercase)")
	}
	if err := (Money{Minor: 1, Currency: "USD"}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMoneyFormatting(t *testing.T) {
	cases := []struct {
		m    Money
		want string
	}{
		{Money{Minor: 1234, Currency: "USD"}, "USD 12.34"},
		{Money{Minor: -50, Currency: "USD"}, "USD -0.50"},
		{Money{Minor: 1234, Currency: "JPY"}, "JPY 1234"},
		{Money{Minor: 1234, Currency: "KWD"}, "KWD 1.234"},
		{Money{Minor: 5, Currency: "ZZZ"}, "ZZZ 0.05"},
	}
	for _, tc := range cases {
		if got := tc.m.String(); got != tc.want {
			t.Fatalf("%v.String() = %q, want %q", tc.m, got, tc.want)
		}
	}
	if got := (Money{Minor: 7}).String(); !strings.Contains(got, "currency not stated") {
		t.Fatalf("unstated amount rendered %q; must not look like a currency figure", got)
	}
}

func TestUSDMConversion(t *testing.T) {
	if m := USDM(100); m.Minor != 10000 || m.Currency != "USD" {
		t.Fatalf("USDM(100) = %v", m)
	}
	if m := USDM(0.29); m.Minor != 29 {
		t.Fatalf("USDM(0.29) = %v", m)
	}
}
