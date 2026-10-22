package verifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"
)

// checkDuplicateJSONKeys checks the closed trust-receipt/v1 objects. Their
// member names must be unique under encoding/json's case-fold matching.
func checkDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return checkJSONValue(dec, nil, true, false)
}

// CheckJSONMembers refuses a JSON value that repeats a member name exactly,
// or spells one struct field of shape twice under encoding/json's
// case-insensitive matching. encoding/json keeps the last spelling while
// most other JSON readers keep the first, so evidence that repeats a member
// can hash one value and display another. Map members stay case-sensitive.
func CheckJSONMembers(raw []byte, shape any) error {
	return checkTypedJSONAliases(raw, shape)
}

// checkTypedJSONAliases follows typed struct members only. V4 profile-owned
// bodies and map keys remain case-sensitive; folding those would change the
// accepted profile contract. Exact duplicates are checked separately for v4.
func checkTypedJSONAliases(raw []byte, value any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return checkJSONValue(dec, reflect.TypeOf(value), false, false)
}

func checkJSONValue(dec *json.Decoder, shape reflect.Type, foldUntyped, rejectNull bool) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if token == nil {
		if rejectNull {
			return fmt.Errorf("explicit null is not a legal v4 member value")
		}
		return nil
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	shape = jsonShape(shape)
	switch delim {
	case '{':
		err = checkJSONObject(dec, shape, foldUntyped, rejectNull)
	case '[':
		err = checkJSONArray(dec, shape, foldUntyped, rejectNull)
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	if err != nil {
		return err
	}
	_, err = dec.Token()
	return err
}

func checkJSONObject(dec *json.Decoder, shape reflect.Type, foldUntyped, rejectNull bool) error {
	seen := make(map[string]struct{})
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("object key has type %T", token)
		}
		comparable := key
		child := jsonMemberShape(shape, key)
		if foldUntyped || (shape != nil && shape.Kind() == reflect.Struct && child != nil) {
			comparable = foldJSONKey(key)
		}
		if _, exists := seen[comparable]; exists {
			return fmt.Errorf("duplicate object key %q", key)
		}
		seen[comparable] = struct{}{}
		if err := checkJSONValue(dec, child, foldUntyped, rejectNull); err != nil {
			return err
		}
	}
	return nil
}

func checkJSONArray(dec *json.Decoder, shape reflect.Type, foldUntyped, rejectNull bool) error {
	var element reflect.Type
	if shape != nil && (shape.Kind() == reflect.Slice || shape.Kind() == reflect.Array) {
		element = shape.Elem()
	}
	for dec.More() {
		if err := checkJSONValue(dec, element, foldUntyped, rejectNull); err != nil {
			return err
		}
	}
	return nil
}

func jsonShape(shape reflect.Type) reflect.Type {
	for shape != nil && shape.Kind() == reflect.Pointer {
		shape = shape.Elem()
	}
	return shape
}

func jsonMemberShape(shape reflect.Type, key string) reflect.Type {
	shape = jsonShape(shape)
	if shape == nil {
		return nil
	}
	if shape.Kind() == reflect.Map {
		return shape.Elem()
	}
	if shape.Kind() != reflect.Struct {
		return nil
	}
	for i := 0; i < shape.NumField(); i++ {
		field := shape.Field(i)
		if field.PkgPath != "" {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if field.Anonymous && name == "" {
			if child := jsonMemberShape(field.Type, key); child != nil {
				return child
			}
		}
		if name == "" {
			name = field.Name
		}
		if foldJSONKey(name) == foldJSONKey(key) {
			return field.Type
		}
	}
	return nil
}

func foldJSONKey(key string) string {
	var folded strings.Builder
	folded.Grow(len(key))
	for _, r := range key {
		if r < utf8.RuneSelf {
			if 'a' <= r && r <= 'z' {
				r -= 'a' - 'A'
			}
		} else {
			r = foldJSONKeyRune(r)
		}
		folded.WriteRune(r)
	}
	return folded.String()
}

func foldJSONKeyRune(r rune) rune {
	for {
		next := unicode.SimpleFold(r)
		if next <= r {
			return next
		}
		r = next
	}
}

// checkStrictJSON is the one structural pass for a v4 value: exact duplicate
// member names, case-folded aliases of typed struct fields, and explicit
// nulls. decodeStrictV4 then fills the value with one DisallowUnknownFields
// decode.
func checkStrictJSON(raw []byte, value any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := checkJSONValue(dec, reflect.TypeOf(value), false, true); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON after the value")
		}
		return fmt.Errorf("trailing JSON after the value: %v", err)
	}
	return nil
}
