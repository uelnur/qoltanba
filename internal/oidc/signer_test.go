package oidc

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSigner_SignVerifyRoundTrip(t *testing.T) {
	s, err := LoadOrGenerate("")
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	if !s.Ephemeral {
		t.Errorf("in-memory key should be ephemeral")
	}
	now := time.Unix(1_700_000_000, 0)
	token, err := s.Sign(map[string]any{"sub": "900130300123", "exp": now.Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims, err := s.Verify(token, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims["sub"] != "900130300123" {
		t.Errorf("sub = %v", claims["sub"])
	}
}

func TestSigner_VerifyRejectsExpired(t *testing.T) {
	s, _ := LoadOrGenerate("")
	now := time.Unix(1_700_000_000, 0)
	token, _ := s.Sign(map[string]any{"exp": now.Add(-time.Minute).Unix()})
	if _, err := s.Verify(token, now); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("err = %v, want ErrTokenExpired", err)
	}
}

func TestSigner_VerifyRejectsTampered(t *testing.T) {
	s, _ := LoadOrGenerate("")
	token, _ := s.Sign(map[string]any{"sub": "x"})
	if _, err := s.Verify(token+"tampered", time.Now()); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
}

func TestSigner_JWKSShape(t *testing.T) {
	s, _ := LoadOrGenerate("")
	set := s.JWKS()
	if len(set.Keys) != 1 {
		t.Fatalf("keys = %d", len(set.Keys))
	}
	k := set.Keys[0]
	if k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" {
		t.Errorf("jwk = %+v", k)
	}
	if k.Kid != s.KeyID() || k.Kid == "" {
		t.Errorf("kid = %q, want %q", k.Kid, s.KeyID())
	}
	if k.N == "" || k.E == "" {
		t.Errorf("missing modulus/exponent: %+v", k)
	}
}

func TestSigner_PersistStableKid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oidc.pem")
	first, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("first LoadOrGenerate: %v", err)
	}
	if first.Ephemeral {
		t.Errorf("persisted key should not be ephemeral")
	}
	second, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("second LoadOrGenerate: %v", err)
	}
	if first.KeyID() != second.KeyID() {
		t.Errorf("kid changed across reload: %q vs %q", first.KeyID(), second.KeyID())
	}
	// A token signed by the first instance verifies under the reloaded key.
	token, _ := first.Sign(map[string]any{"sub": "s", "exp": time.Now().Add(time.Hour).Unix()})
	if _, err := second.Verify(token, time.Now()); err != nil {
		t.Errorf("reloaded key cannot verify: %v", err)
	}
}
