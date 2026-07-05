//go:build qoltanba_functional

package e2e

import (
	"context"
	"os"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
)

// TestFunctionalE2E_TSP signs with an RFC 3161 timestamp from the test TSA and
// checks verify surfaces the parsed TSP token and CAdES level T. Needs network to
// the TSA responder.
func TestFunctionalE2E_TSP(t *testing.T) {
	svc, closer := newService(t)
	defer closer()
	key := testKey(t)

	// The default TSA baked into Kalkan is the production responder, which will not
	// timestamp a test certificate; the test responder must be named explicitly.
	signed, err := svc.Sign(context.Background(), core.SignInput{
		Format: core.FormatCMS, Data: []byte("tsp"), Key: key, WithTimestamp: boolPtr(true),
		OutputPEM: true, TSAURL: os.Getenv("QOLTANBA_TSA_URL"),
	})
	if err != nil {
		t.Fatalf("sign+tsp: %v (network to TSA required; lib %+v)", err, signed.LibError)
	}
	out, err := svc.Verify(context.Background(), core.VerifyInput{Format: core.FormatCMS, Signature: signed.Signature, InputPEM: true})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(out.Signers) == 0 {
		t.Fatalf("no signers (valid=%v libErr=%+v)", out.Valid, out.LibError)
	}
	ts := out.Signers[0].Timestamp
	if ts == nil {
		t.Fatal("expected a parsed TSP timestamp")
	}
	if ts.GenTime == nil {
		t.Error("expected TSP genTime")
	}
	if out.Signers[0].CAdESLevel != "T" {
		t.Errorf("cadesLevel = %q, want T", out.Signers[0].CAdESLevel)
	}
	t.Logf("TSP: genTime=%v serial=%q policy=%q hashAlg=%q tsa=%q",
		ts.GenTime, ts.SerialNumber, ts.Policy, ts.HashAlgorithm, ts.TSA)
}
