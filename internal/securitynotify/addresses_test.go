package securitynotify

import (
	"errors"
	"regexp"
	"testing"
)

func TestAnAddressIsOneBareEmail(t *testing.T) {
	for raw, ok := range map[string]bool{
		"person@example.com":              true,
		"  person@example.com ":           true,
		"Person <person@example.com>":     false,
		"person@example.com, b@example.c": false,
		"not an address":                  false,
		"":                                false,
		string(make([]byte, 300)) + "@x":  false,
	} {
		_, err := normalized(raw)
		if (err == nil) != ok || (err != nil && !errors.Is(err, ErrInvalidAddress)) {
			t.Errorf("%q: err %v, want accepted %t", raw, err, ok)
		}
	}
}

func TestAMaskedAddressShowsItsFirstLetterAndDomain(t *testing.T) {
	for in, want := range map[string]string{"alice@example.com": "a***@example.com", "x@y": "x***@y", "broken": "***"} {
		if got := Mask(in); got != want {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAProofCodeIsEightDigits(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		code, err := proofCode()
		if err != nil || !regexp.MustCompile(`^[0-9]{8}$`).MatchString(code) {
			t.Fatalf("code %q, %v", code, err)
		}
		seen[code] = true
	}
	if len(seen) < 45 {
		t.Errorf("50 codes held %d distinct values", len(seen))
	}
}
