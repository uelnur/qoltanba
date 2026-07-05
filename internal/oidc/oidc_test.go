package oidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// fakeVerifier is a canned domain double implementing the narrow Verifier port,
// so the flow is tested without Kalkan or the full core.Service.
type fakeVerifier struct {
	verifyOut   core.VerifyOutput
	verifyErr   error
	validateOut core.ValidateOutput
	validateErr error
	lastVerify  core.VerifyInput
}

func (f *fakeVerifier) Verify(_ context.Context, in core.VerifyInput) (core.VerifyOutput, error) {
	f.lastVerify = in
	return f.verifyOut, f.verifyErr
}

func (f *fakeVerifier) Validate(_ context.Context, _ core.ValidateInput) (core.ValidateOutput, error) {
	return f.validateOut, f.validateErr
}

func goodVerifier() *fakeVerifier {
	return &fakeVerifier{
		verifyOut: core.VerifyOutput{
			Valid: true,
			Signers: []core.Signer{{
				Certificate: core.Certificate{PEM: []byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")},
				Valid:       true,
				Claims: &core.Claims{
					Sub: "900130300123", IIN: "900130300123",
					Name: "ТЕСТ ТЕСТОВ", Roles: []string{"INDIVIDUAL"},
				},
			}},
		},
		validateOut: core.ValidateOutput{Status: core.RevocationStatus{Revoked: false}},
	}
}

func newProvider(t *testing.T, v Verifier, cfg Config, clock *time.Time) *Provider {
	t.Helper()
	signer, err := LoadOrGenerate("")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "https://auth.example.kz"
	}
	return New(v, signer, NewMemStore(), cfg, WithClock(func() time.Time { return *clock }))
}

func TestFlow_HappyPath(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	v := goodVerifier()
	p := newProvider(t, v, Config{RequireOCSP: true}, &clock)
	ctx := context.Background()

	ch, err := p.Challenge(ctx, ChallengeRequest{Nonce: "rp-nonce", State: "st"})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if ch.State != "st" || ch.ChallengeID == "" || ch.Data == "" {
		t.Fatalf("challenge = %+v", ch)
	}

	tok, err := p.Verify(ctx, VerifyRequest{ChallengeID: ch.ChallengeID, Signature: []byte("cms")})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if tok.TokenType != "Bearer" || tok.IDToken == "" || tok.AccessToken == "" {
		t.Fatalf("token = %+v", tok)
	}

	// The domain was asked to verify a detached CMS over the exact nonce, with claims.
	if !v.lastVerify.Detached || !v.lastVerify.ExtractClaims || v.lastVerify.Format != core.FormatCMS {
		t.Errorf("verify input = %+v", v.lastVerify)
	}
	wantNonce, _ := base64.StdEncoding.DecodeString(ch.Data)
	if !bytes.Equal(v.lastVerify.Data, wantNonce) {
		t.Errorf("signed data does not match issued nonce")
	}

	// The id_token verifies under the JWKS key and carries the identity claims.
	claims, err := p.Signer().Verify(tok.IDToken, clock)
	if err != nil {
		t.Fatalf("id_token verify: %v", err)
	}
	if claims["sub"] != "900130300123" || claims["iss"] != "https://auth.example.kz" {
		t.Errorf("id_token claims = %+v", claims)
	}
	if claims["iin"] != "900130300123" || claims["nonce"] != "rp-nonce" {
		t.Errorf("id_token missing RK/nonce claims: %+v", claims)
	}
	if claims["aud"] != "https://auth.example.kz" {
		t.Errorf("aud = %v", claims["aud"])
	}
}

func TestFlow_UserInfo(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	p := newProvider(t, goodVerifier(), Config{}, &clock)
	ctx := context.Background()
	ch, _ := p.Challenge(ctx, ChallengeRequest{})
	tok, err := p.Verify(ctx, VerifyRequest{ChallengeID: ch.ChallengeID, Signature: []byte("cms")})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	claims, err := p.UserInfo(ctx, tok.AccessToken)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if claims["sub"] != "900130300123" || claims["token_use"] != "access" {
		t.Errorf("userinfo claims = %+v", claims)
	}
}

func TestFlow_ClientIDBecomesAudience(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	p := newProvider(t, goodVerifier(), Config{}, &clock)
	ctx := context.Background()
	ch, _ := p.Challenge(ctx, ChallengeRequest{})
	tok, _ := p.Verify(ctx, VerifyRequest{ChallengeID: ch.ChallengeID, Signature: []byte("cms"), ClientID: "my-app"})
	claims, _ := p.Signer().Verify(tok.IDToken, clock)
	if claims["aud"] != "my-app" {
		t.Errorf("aud = %v, want my-app", claims["aud"])
	}
}

func TestFlow_Replay(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	p := newProvider(t, goodVerifier(), Config{}, &clock)
	ctx := context.Background()
	ch, _ := p.Challenge(ctx, ChallengeRequest{})
	if _, err := p.Verify(ctx, VerifyRequest{ChallengeID: ch.ChallengeID, Signature: []byte("cms")}); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if _, err := p.Verify(ctx, VerifyRequest{ChallengeID: ch.ChallengeID, Signature: []byte("cms")}); !errors.Is(err, ErrChallengeUsed) {
		t.Fatalf("replay err = %v, want ErrChallengeUsed", err)
	}
}

func TestFlow_Expired(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	p := newProvider(t, goodVerifier(), Config{ChallengeTTL: time.Minute}, &clock)
	ctx := context.Background()
	ch, _ := p.Challenge(ctx, ChallengeRequest{})
	clock = clock.Add(2 * time.Minute)
	if _, err := p.Verify(ctx, VerifyRequest{ChallengeID: ch.ChallengeID, Signature: []byte("cms")}); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("err = %v, want ErrChallengeExpired", err)
	}
}

func TestFlow_UnknownChallenge(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	p := newProvider(t, goodVerifier(), Config{}, &clock)
	if _, err := p.Verify(context.Background(), VerifyRequest{ChallengeID: "nope", Signature: []byte("cms")}); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("err = %v, want ErrChallengeNotFound", err)
	}
}

func TestFlow_InvalidSignature(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	v := goodVerifier()
	v.verifyOut.Valid = false // signature did not verify (soft failure)
	p := newProvider(t, v, Config{}, &clock)
	ctx := context.Background()
	ch, _ := p.Challenge(ctx, ChallengeRequest{})
	if _, err := p.Verify(ctx, VerifyRequest{ChallengeID: ch.ChallengeID, Signature: []byte("cms")}); !errors.Is(err, ErrSignatureRejected) {
		t.Fatalf("err = %v, want ErrSignatureRejected", err)
	}
}

func TestFlow_Revoked(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	v := goodVerifier()
	v.validateOut.Status.Revoked = true
	p := newProvider(t, v, Config{RequireOCSP: true}, &clock)
	ctx := context.Background()
	ch, _ := p.Challenge(ctx, ChallengeRequest{})
	if _, err := p.Verify(ctx, VerifyRequest{ChallengeID: ch.ChallengeID, Signature: []byte("cms")}); !errors.Is(err, ErrCertRevoked) {
		t.Fatalf("err = %v, want ErrCertRevoked", err)
	}
}

func TestFlow_SkipOCSP(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	v := goodVerifier()
	v.validateOut.Status.Revoked = true // would reject, but RequireOCSP is off
	p := newProvider(t, v, Config{RequireOCSP: false}, &clock)
	ctx := context.Background()
	ch, _ := p.Challenge(ctx, ChallengeRequest{})
	if _, err := p.Verify(ctx, VerifyRequest{ChallengeID: ch.ChallengeID, Signature: []byte("cms")}); err != nil {
		t.Fatalf("Verify with OCSP off: %v", err)
	}
}

func TestDiscovery(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	p := newProvider(t, goodVerifier(), Config{Issuer: "https://auth.example.kz/"}, &clock)
	d := p.Discovery()
	if d.Issuer != "https://auth.example.kz/" {
		t.Errorf("issuer = %q", d.Issuer)
	}
	if d.JWKSURI != "https://auth.example.kz/oidc/jwks.json" {
		t.Errorf("jwks_uri = %q", d.JWKSURI)
	}
	if len(d.IDTokenSigningAlgValuesSupported) == 0 || d.IDTokenSigningAlgValuesSupported[0] != "RS256" {
		t.Errorf("alg = %v", d.IDTokenSigningAlgValuesSupported)
	}
}
