package core

import (
	"context"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/provider"
)

// stubOCSPCache records interactions so a test can assert what the domain asked
// for and what it stored.
type stubOCSPCache struct {
	answer    OCSPAnswer
	hit       bool
	lookups   int
	stored    *OCSPAnswer
	storedFor string
}

func (s *stubOCSPCache) Lookup(_ []byte, responder string) (OCSPAnswer, bool) {
	s.lookups++
	s.storedFor = responder
	return s.answer, s.hit
}

func (s *stubOCSPCache) Store(_ []byte, responder string, a OCSPAnswer) {
	s.stored, s.storedFor = &a, responder
}

// TestValidate_CacheHitSkipsTheLibrary is the whole point of the cache: a hit
// must not reach the driver, which is what spares the responder.
func TestValidate_CacheHitSkipsTheLibrary(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	revoked := now.Add(-24 * time.Hour)
	cache := &stubOCSPCache{hit: true, answer: OCSPAnswer{
		Revoked: true, Reason: "superseded", RevocationTime: &revoked, Response: []byte("cached-resp"),
	}}
	prov := &fakeProvider{}
	svc := New(prov, WithOCSPCache(cache), WithClock(func() time.Time { return now }))

	out, err := svc.Validate(context.Background(), ValidateInput{
		Cert: []byte("cert"), Format: EncodingDER, Method: MethodOCSP,
		ResponderURL: "http://ocsp.pki.gov.kz", WantOCSP: true,
	})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if prov.lastValidate != nil {
		t.Error("a cache hit still called the library")
	}
	if !out.Status.Revoked || out.Status.Reason != "superseded" {
		t.Errorf("verdict lost: %+v", out.Status)
	}
	if string(out.OCSPResponse) != "cached-resp" {
		t.Errorf("stapled response = %q, want the cached bytes", out.OCSPResponse)
	}
	// CheckedAt is when this caller was answered, not when the responder replied.
	if out.Status.CheckedAt == nil || !out.Status.CheckedAt.Equal(now) {
		t.Errorf("checkedAt = %v, want %v", out.Status.CheckedAt, now)
	}
}

func TestValidate_CacheMissStoresTheAnswer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cache := &stubOCSPCache{hit: false}
	prov := &fakeProvider{validateResult: provider.ValidateResult{
		Status: provider.StatusGood, OCSPResponse: []byte("fresh"),
	}}
	svc := New(prov, WithOCSPCache(cache), WithClock(func() time.Time { return now }))

	if _, err := svc.Validate(context.Background(), ValidateInput{
		Cert: []byte("cert"), Format: EncodingDER, Method: MethodOCSP,
		ResponderURL: "http://ocsp.pki.gov.kz",
	}); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if prov.lastValidate == nil {
		t.Fatal("a miss must reach the library")
	}
	if cache.stored == nil {
		t.Fatal("the fresh answer was not cached")
	}
	if string(cache.stored.Response) != "fresh" {
		t.Errorf("cached response = %q, want the responder's bytes", cache.stored.Response)
	}
	if cache.storedFor != "http://ocsp.pki.gov.kz" {
		t.Errorf("cached under responder %q", cache.storedFor)
	}
}

// TestValidate_CRLPathIsNotCached keeps the cache to the path it understands.
func TestValidate_CRLPathIsNotCached(t *testing.T) {
	cache := &stubOCSPCache{}
	prov := &fakeProvider{validateResult: provider.ValidateResult{Status: provider.StatusGood}}
	svc := New(prov, WithOCSPCache(cache))

	if _, err := svc.Validate(context.Background(), ValidateInput{
		Cert: []byte("cert"), Format: EncodingDER, Method: MethodCRL, CRL: []byte("crl"),
	}); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cache.lookups != 0 || cache.stored != nil {
		t.Errorf("CRL validation touched the OCSP cache: %d lookups, stored=%v", cache.lookups, cache.stored != nil)
	}
}
