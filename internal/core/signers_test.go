package core

import (
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/cms"
)

func TestNormHex(t *testing.T) {
	cases := map[string]string{
		"00ABCD": "ABCD", "abcd": "ABCD", "0000": "0", "6C4256": "6C4256", "  6c4256  ": "6C4256",
	}
	for in, want := range cases {
		if got := normHex(in); got != want {
			t.Errorf("normHex(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSigAlgName(t *testing.T) {
	if got := sigAlgName("1.2.398.3.10.1.1.2.3.2"); got != "GOST R 34.10-2015 512" {
		t.Errorf("gost512 = %q", got)
	}
	if got := sigAlgName("1.2.840.113549.1.1.11"); got != "SHA256withRSA" {
		t.Errorf("rsa = %q", got)
	}
	if got := sigAlgName("9.9.9"); got != "9.9.9" {
		t.Errorf("unknown fallback = %q", got)
	}
}

func TestTimestampFromCMS(t *testing.T) {
	gt := time.Date(2026, 5, 8, 6, 45, 13, 0, time.UTC)
	ts := timestampFromCMS(&cms.Timestamp{
		SerialNumberHex: "1234", GenTime: &gt, Policy: "1.2.398.3.3.2.6.4",
		HashAlgorithmOID: "2.16.840.1.101.3.4.2.1", Hash: []byte{1, 2}, TSA: "tsa",
	})
	if ts.SerialNumber != "1234" || ts.Policy != "1.2.398.3.3.2.6.4" || ts.TSA != "tsa" {
		t.Errorf("unexpected timestamp %+v", ts)
	}
	if ts.HashAlgorithm != "SHA256" {
		t.Errorf("hashAlgorithm = %q, want SHA256 (resolved from OID)", ts.HashAlgorithm)
	}
}
