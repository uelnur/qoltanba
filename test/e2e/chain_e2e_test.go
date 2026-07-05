//go:build qoltanba_functional

package e2e

import (
	"context"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/keysource"
)

// TestFunctionalE2E_ChainVerified builds the signer chain to the test root and
// has Kalkan cryptographically validate the GOST chain (the check Go cannot do).
func TestFunctionalE2E_ChainVerified(t *testing.T) {
	pool := requirePool(t)
	svc := core.New(pool,
		core.WithKeySource(keysource.New(keysource.WithInline(true))),
		core.WithTrustStore(loadEnvTrust(t)),
		core.WithChainVerification(true),
	)
	key := testKey(t)

	signed, err := svc.Sign(context.Background(), core.SignInput{Format: core.FormatCMS, Data: []byte("chain"), Key: key, OutputPEM: true})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, err := svc.Verify(context.Background(), core.VerifyInput{Format: core.FormatCMS, Signature: signed.Signature, InputPEM: true})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(out.Signers) == 0 {
		t.Fatal("no signers")
	}
	s := out.Signers[0]
	t.Logf("chainComplete=%v trustAnchorFound=%v chainSignaturesVerified=%v chainLen=%d",
		s.ChainComplete, s.TrustAnchorFound, s.ChainSignaturesVerified, len(s.Chain))
	if !s.ChainComplete {
		t.Error("expected a complete chain to the test root")
	}
	if !s.ChainSignaturesVerified {
		t.Error("expected Kalkan to cryptographically validate the GOST chain")
	}
}
