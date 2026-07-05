//go:build qoltanba_functional

package native

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/oidc"
	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/trust"
)

// oidcTrustStore builds a trust store from the test NUC CAs (QOLTANBA_CA_ROOT /
// QOLTANBA_CA_NCA), PEM-wrapping the DER fixtures into a temp directory that
// trust.LoadDir reads. OIDC needs these anchors: CheckCertTime forces Kalkan to
// validate the signer chain to a trusted root, which is the auth boundary — a
// cert that does not chain to a NUC root must not grant a login. Skips the test
// when no CAs are provided (an offline environment).
func oidcTrustStore(t *testing.T) *trust.Store {
	t.Helper()
	cas := trustedCAs(t)
	if len(cas) == 0 {
		t.Skip("no trusted CAs (set QOLTANBA_CA_ROOT/QOLTANBA_CA_NCA) — OIDC chain validation needs them")
	}
	dir := t.TempDir()
	for i, ca := range cas {
		blob := ca.Cert
		if p, _ := pem.Decode(ca.Cert); p == nil { // raw DER fixture → wrap as PEM
			blob = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert})
		}
		if err := os.WriteFile(filepath.Join(dir, "ca"+string(rune('0'+i))+".pem"), blob, 0o600); err != nil {
			t.Fatalf("write CA: %v", err)
		}
	}
	store, err := trust.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if store.Count() == 0 {
		t.Fatalf("trust store empty after loading %d CAs", len(cas))
	}
	return store
}

// TestFunctional_OIDCLoginFlow drives the whole "login with ЭЦП" flow against the
// REAL library: the OIDC provider issues a challenge, the test key signs that
// nonce as a detached CMS through Kalkan, the provider verifies it (real GOST
// verification via core) and mints an RS256 id_token/access_token, and the token
// verifies under the published JWKS with the signer's identity as its subject.
//
// OCSP is off here so the test is offline and deterministic; the OCSP/revocation
// leg is exercised at the driver level by TestFunctional_Revocation and at the
// flow level by the internal/oidc unit tests.
func TestFunctional_OIDCLoginFlow(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	ctx := context.Background()

	svc := core.New(p, core.WithTrustStore(oidcTrustStore(t)))
	signer, err := oidc.LoadOrGenerate("")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	prov := oidc.New(svc, signer, oidc.NewMemStore(), oidc.Config{
		Issuer:      "https://auth.test.local",
		RequireOCSP: false, // offline: chain+time enforced via CheckCertTime; OCSP leg covered by TestFunctional_Revocation
	})

	// 1. Challenge — the server tells the client what to sign.
	ch, err := prov.Challenge(ctx, oidc.ChallengeRequest{Nonce: "rp-nonce-123", State: "st-abc"})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if ch.ChallengeID == "" || ch.State != "st-abc" {
		t.Fatalf("challenge = %+v", ch)
	}
	nonce, err := base64.StdEncoding.DecodeString(ch.Data)
	if err != nil || len(nonce) == 0 {
		t.Fatalf("challenge data not base64: %v", err)
	}

	// 2. The user signs the nonce as a detached CMS with the real test key.
	sig, err := p.SignCMS(ctx, provider.SignRequest{Key: envKey(), Data: nonce, Detached: true, OutPEM: true})
	if err != nil {
		t.Fatalf("SignCMS detached: %v", err)
	}

	// 3. Verify — real GOST verification through core, then token minting.
	tok, err := prov.Verify(ctx, oidc.VerifyRequest{ChallengeID: ch.ChallengeID, Signature: sig.Signature})
	if err != nil {
		t.Fatalf("oidc Verify: %v", err)
	}
	if tok.TokenType != "Bearer" || tok.IDToken == "" || tok.AccessToken == "" {
		t.Fatalf("token = %+v", tok)
	}

	// 4. The id_token verifies under the JWKS key and carries the signer identity.
	claims, err := signer.Verify(tok.IDToken, time.Now())
	if err != nil {
		t.Fatalf("id_token verify: %v", err)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		t.Fatalf("id_token has no subject: %+v", claims)
	}
	if claims["iss"] != "https://auth.test.local" {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["nonce"] != "rp-nonce-123" {
		t.Errorf("rp nonce not bound into id_token: %v", claims["nonce"])
	}
	t.Logf("issued id_token for sub=%q iin=%v name=%v", sub, claims["iin"], claims["name"])

	// 5. UserInfo returns the same subject for the access token.
	ui, err := prov.UserInfo(ctx, tok.AccessToken)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if ui["sub"] != sub {
		t.Errorf("userinfo sub = %v, want %q", ui["sub"], sub)
	}

	// 6. Anti-replay: the same challenge cannot be verified twice.
	if _, err := prov.Verify(ctx, oidc.VerifyRequest{ChallengeID: ch.ChallengeID, Signature: sig.Signature}); !errors.Is(err, oidc.ErrChallengeUsed) {
		t.Fatalf("replay err = %v, want ErrChallengeUsed", err)
	}
}

// TestFunctional_OIDCRejectsForeignSignature confirms the flow rejects a
// signature made over different bytes than the issued nonce (a signature that is
// cryptographically valid on its own but not bound to this challenge).
func TestFunctional_OIDCRejectsForeignSignature(t *testing.T) {
	p := openPool(t, 1, false)
	defer p.Close()
	ctx := context.Background()

	svc := core.New(p, core.WithTrustStore(oidcTrustStore(t)))
	signer, err := oidc.LoadOrGenerate("")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	prov := oidc.New(svc, signer, oidc.NewMemStore(), oidc.Config{Issuer: "https://auth.test.local", RequireOCSP: false})

	ch, err := prov.Challenge(ctx, oidc.ChallengeRequest{})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	// Sign unrelated data, not the challenge nonce.
	sig, err := p.SignCMS(ctx, provider.SignRequest{Key: envKey(), Data: []byte("some other payload"), Detached: true, OutPEM: true})
	if err != nil {
		t.Fatalf("SignCMS: %v", err)
	}

	_, err = prov.Verify(ctx, oidc.VerifyRequest{ChallengeID: ch.ChallengeID, Signature: sig.Signature})
	if !errors.Is(err, oidc.ErrSignatureRejected) {
		t.Fatalf("foreign-signature err = %v, want ErrSignatureRejected", err)
	}
}
