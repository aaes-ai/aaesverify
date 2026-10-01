package types

import (
	"errors"
	"math"
	"testing"
)

func TestMoneyArithmeticBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name               string
		a, b, want         int64
		subtract, overflow bool
	}{
		{name: "add positive overflow", a: math.MaxInt64, b: 1, overflow: true},
		{name: "add negative overflow", a: math.MinInt64, b: -1, overflow: true},
		{name: "add maximum", a: math.MaxInt64 - 1, b: 1, want: math.MaxInt64},
		{name: "add minimum", a: math.MinInt64 + 1, b: -1, want: math.MinInt64},
		{name: "add opposite extremes", a: math.MaxInt64, b: math.MinInt64, want: -1},
		{name: "subtract positive overflow", a: math.MinInt64, b: 1, subtract: true, overflow: true},
		{name: "subtract negative overflow", a: math.MaxInt64, b: -1, subtract: true, overflow: true},
		{name: "subtract minimum from zero", a: 0, b: math.MinInt64, subtract: true, overflow: true},
		{name: "subtract minimum from minimum", a: math.MinInt64, b: math.MinInt64, subtract: true, want: 0},
		{name: "subtract maximum", a: 0, b: -math.MaxInt64, subtract: true, want: math.MaxInt64},
		{name: "subtract minimum", a: -1, b: math.MaxInt64, subtract: true, want: math.MinInt64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := Money{Minor: tc.a, Currency: "USD"}, Money{Minor: tc.b, Currency: "USD"}
			var got Money
			var err error
			if tc.subtract {
				got, err = a.Sub(b)
			} else {
				got, err = a.Add(b)
			}
			if tc.overflow {
				if !errors.Is(err, ErrMoneyOverflow) || got != (Money{}) {
					t.Fatalf("got %v, %v", got, err)
				}
				return
			}
			if err != nil || got.Minor != tc.want || got.Currency != "USD" {
				t.Fatalf("got %v, %v; want %d USD minor", got, err, tc.want)
			}
		})
	}
}
