//go:build qoltanba_functional

package native

import (
	"context"
	"os"
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
)

// TestFunctional_HashSignHash computes a digest and signs it (the basis for
// streaming signatures and GOST JWT).
func TestFunctional_HashSignHash(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	ctx := context.Background()
	if !p.Capabilities().Hash {
		t.Skip("HashData/SignHash unavailable")
	}
	// The HashData algorithm name is found empirically. Order: first the surely
	// supported ones (SHA/GOST34311-95) to prove the plumbing, then GOST-2015-512
	// candidates for SignHash under a GOST key (which needs a 64-byte digest).
	candidates := []string{
		"1.2.398.3.10.1.1.1.2", "1.2.398.3.10.1.1.1.3", // GOST-2015 (512), if supported
		"GOST3411-2015-512", "GOST34311_2015_512", "1.2.643.7.1.1.2.3",
		"GOST34311", "1.2.398.3.10.1.1.1", // GOST-95
		"SHA256", "2.16.840.1.101.3.4.2.1", "SHA1", "1.3.14.3.2.26", "MD5", // plumbing check
	}
	if e := os.Getenv("QOLTANBA_HASH_ALG"); e != "" {
		candidates = append([]string{e}, candidates...)
	}
	var alg string
	var h provider.HashResult
	for _, c := range candidates {
		out, err := p.Hash(ctx, provider.HashRequest{Algorithm: c, Data: testData})
		if err == nil && len(out.Hash) > 0 {
			alg, h = c, out
			break
		}
	}
	if alg == "" {
		t.Skip("no HashData candidate worked (set QOLTANBA_HASH_ALG)")
	}
	t.Logf("HashData works: algorithm %q -> %d-byte digest", alg, len(h.Hash))

	// SignHash only makes sense when the digest fits the GOST-2015-512 key
	// (64 bytes). Otherwise (SHA/GOST-95) the HashData plumbing is proven and
	// SignHash is skipped.
	if len(h.Hash) != 64 {
		t.Logf("%d-byte digest does not fit a GOST-512 key — SignHash skipped (standalone GOST-2015 in HashData appears unavailable)", len(h.Hash))
		return
	}
	sig, err := p.SignHash(ctx, provider.SignHashRequest{Key: envKey(), Hash: h.Hash, OutPEM: true})
	if err != nil {
		t.Fatalf("SignHash: %v", err)
	}
	if len(sig.Signature) == 0 {
		t.Fatal("empty hash signature")
	}
	t.Logf("SignHash: %d-byte signature", len(sig.Signature))
}
