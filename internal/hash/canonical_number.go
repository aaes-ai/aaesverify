package hash

import (
	"bytes"
	"fmt"
	"math/big"
	"strconv"
)

// maxJSONExp is the largest |exponent| (or combined decimal shift) a JSON
// number may carry. Larger values are refused rather than expanded into
// unbounded digit strings.
const maxJSONExp = 100000

var ten = big.NewInt(10)

type parsedJSONNumber struct {
	neg        bool
	intDigits  string
	fracDigits string
	exp        int
}

func canonicalJSONNumber(s string) (string, error) {
	p, err := parseJSONNumber(s)
	if err != nil {
		return "", err
	}
	return formatCanonicalNumber(s, p)
}

func parseJSONNumber(s string) (parsedJSONNumber, error) {
	neg, i, err := scanJSONSign(s)
	if err != nil {
		return parsedJSONNumber{}, err
	}
	intDigits, i, err := parseJSONIntDigits(s, i)
	if err != nil {
		return parsedJSONNumber{}, err
	}
	fracDigits, i, err := parseJSONFracDigits(s, i)
	if err != nil {
		return parsedJSONNumber{}, err
	}
	exp, i, err := parseJSONExponent(s, i)
	if err != nil {
		return parsedJSONNumber{}, err
	}
	if i != len(s) {
		return parsedJSONNumber{}, fmt.Errorf("hash: invalid JSON number %q", s)
	}
	if exp > maxJSONExp || exp < -maxJSONExp {
		return parsedJSONNumber{}, fmt.Errorf("hash: JSON number %q exponent exceeds %d", s, maxJSONExp)
	}
	return parsedJSONNumber{neg: neg, intDigits: intDigits, fracDigits: fracDigits, exp: exp}, nil
}

func scanJSONSign(s string) (bool, int, error) {
	if s == "" {
		return false, 0, fmt.Errorf("hash: empty JSON number")
	}
	if s[0] != '-' {
		return false, 0, nil
	}
	if len(s) == 1 {
		return false, 0, fmt.Errorf("hash: invalid JSON number %q", s)
	}
	return true, 1, nil
}

func parseJSONIntDigits(s string, i int) (string, int, error) {
	if i >= len(s) || s[i] < '0' || s[i] > '9' {
		return "", 0, fmt.Errorf("hash: invalid JSON number %q", s)
	}
	intStart := i
	if s[i] == '0' {
		i++
		if i < len(s) && s[i] >= '0' && s[i] <= '9' {
			return "", 0, fmt.Errorf("hash: invalid JSON number %q", s)
		}
		return s[intStart:i], i, nil
	}
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[intStart:i], i, nil
}

func parseJSONFracDigits(s string, i int) (string, int, error) {
	if i >= len(s) || s[i] != '.' {
		return "", i, nil
	}
	i++
	fracStart := i
	if i >= len(s) || s[i] < '0' || s[i] > '9' {
		return "", 0, fmt.Errorf("hash: invalid JSON number %q", s)
	}
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[fracStart:i], i, nil
}

func parseJSONExponent(s string, i int) (int, int, error) {
	if i >= len(s) || (s[i] != 'e' && s[i] != 'E') {
		return 0, i, nil
	}
	i++
	expSign := 1
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		if s[i] == '-' {
			expSign = -1
		}
		i++
	}
	if i >= len(s) || s[i] < '0' || s[i] > '9' {
		return 0, 0, fmt.Errorf("hash: invalid JSON number %q", s)
	}
	e, i, err := parseExpDigits(s, i)
	if err != nil {
		return 0, 0, err
	}
	return expSign * e, i, nil
}

func parseExpDigits(s string, i int) (int, int, error) {
	e := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		d := int(s[i] - '0')
		if e > (maxJSONExp-d)/10 {
			return 0, 0, fmt.Errorf("hash: JSON number %q exponent exceeds %d", s, maxJSONExp)
		}
		e = e*10 + d
		i++
	}
	return e, i, nil
}

func formatCanonicalNumber(s string, p parsedJSONNumber) (string, error) {
	digits := p.intDigits + p.fracDigits
	mant := new(big.Int)
	if _, ok := mant.SetString(digits, 10); !ok {
		return "", fmt.Errorf("hash: invalid JSON number %q", s)
	}
	adj := p.exp - len(p.fracDigits)
	if adj > maxJSONExp || adj < -maxJSONExp {
		return "", fmt.Errorf("hash: JSON number %q exponent exceeds %d", s, maxJSONExp)
	}
	if adj >= 0 {
		return formatCanonicalInt(s, p.neg, digits, mant, adj)
	}
	return formatCanonicalFrac(s, p.neg, mant, adj)
}

func formatCanonicalInt(s string, neg bool, digits string, mant *big.Int, adj int) (string, error) {
	if nz := trimLeadingZeros(digits); len(nz)+adj > maxJSONExp+1 {
		return "", fmt.Errorf("hash: JSON number %q expands beyond %d digits", s, maxJSONExp)
	}
	if adj > 0 {
		pow := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(adj)), nil)
		mant.Mul(mant, pow)
	}
	return signedInt(neg, mant), nil
}

func formatCanonicalFrac(s string, neg bool, mant *big.Int, adj int) (string, error) {
	den := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(-adj)), nil)
	rat := new(big.Rat).SetFrac(mant, den)
	if rat.IsInt() {
		return signedInt(neg, rat.Num()), nil
	}

	num := new(big.Int).Set(rat.Num())
	den = new(big.Int).Set(rat.Denom())
	quo, rem := new(big.Int).QuoRem(num, den, new(big.Int))
	frac := make([]byte, 0, 16)
	for rem.Sign() != 0 {
		rem.Mul(rem, ten)
		d, newRem := new(big.Int).QuoRem(rem, den, new(big.Int))
		frac = append(frac, byte('0'+d.Int64()))
		rem = newRem
		if len(frac) > maxJSONExp {
			return "", fmt.Errorf("hash: JSON number %q has a non-terminating decimal longer than %d digits", s, maxJSONExp)
		}
	}
	out := quo.String() + "." + string(frac)
	if neg {
		out = "-" + out
	}
	return out, nil
}

func trimLeadingZeros(s string) string {
	i := 0
	for i < len(s)-1 && s[i] == '0' {
		i++
	}
	return s[i:]
}

func signedInt(neg bool, n *big.Int) string {
	if n.Sign() == 0 {
		return "0"
	}
	if neg {
		return "-" + n.String()
	}
	return n.String()
}

// writeSignedInt writes any signed integer width as exact decimal text,
// because a canonical integer is emitted exactly rather than rounded.
func writeSignedInt(buf *bytes.Buffer, v any) {
	var n int64
	switch t := v.(type) {
	case int:
		n = int64(t)
	case int8:
		n = int64(t)
	case int16:
		n = int64(t)
	case int32:
		n = int64(t)
	case int64:
		n = t
	}
	buf.WriteString(strconv.FormatInt(n, 10))
}

// writeUnsignedInt writes any unsigned integer width as exact decimal text.
func writeUnsignedInt(buf *bytes.Buffer, v any) {
	var n uint64
	switch t := v.(type) {
	case uint:
		n = uint64(t)
	case uint8:
		n = uint64(t)
	case uint16:
		n = uint64(t)
	case uint32:
		n = uint64(t)
	case uint64:
		n = t
	}
	buf.WriteString(strconv.FormatUint(n, 10))
}
