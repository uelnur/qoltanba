package native

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestDigestMatches(t *testing.T) {
	sum := sha256.Sum256(selfTestVector)
	want := sum[:]

	cases := []struct {
		name string
		got  []byte
		ok   bool
	}{
		{"raw", want, true},
		{"hex-lower", []byte(hex.EncodeToString(want)), true},
		{"hex-upper", []byte(toUpperASCII(hex.EncodeToString(want))), true},
		{"base64", []byte(base64.StdEncoding.EncodeToString(want)), true},
		{"raw-trailing-nul", append(append([]byte{}, want...), 0, 0), true}, // NUL padding tolerated
		{"hex-trailing-newline", []byte(hex.EncodeToString(want) + "\n"), true},
		{"wrong", []byte("not-a-digest"), false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		if got := digestMatches(c.got, want); got != c.ok {
			t.Errorf("%s: digestMatches = %v, want %v", c.name, got, c.ok)
		}
	}
}

// toUpperASCII avoids importing strings for a single call in the test.
func toUpperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
