package core

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/uelnur/qoltanba/internal/cms"
	"github.com/uelnur/qoltanba/internal/pki"
	"github.com/uelnur/qoltanba/internal/provider"
)

// CAdES-T claims a timestamp over *this* signature. A token is an attribute like
// any other, so the claim only holds once its message imprint is shown to be the
// digest of this signature value — otherwise a token lifted from another
// container reads exactly the same.

func signerWithToken(sig []byte, hashOID string, imprint []byte) cms.SignerInfo {
	return cms.SignerInfo{
		Signature: sig,
		Timestamp: &cms.Timestamp{HashAlgorithmOID: hashOID, Hash: imprint},
	}
}

func TestVerifyTimestampImprint_MatchingSHA256(t *testing.T) {
	sig := []byte("signature-value")
	sum := sha256.Sum256(sig)
	svc := New(&fakeProvider{})

	verified, note := svc.verifyTimestampImprint(context.Background(),
		signerWithToken(sig, pki.DigestSHA256, sum[:]))
	if verified == nil || !*verified {
		t.Fatalf("a token over this signature must verify (note: %q)", note)
	}
	if note != "" {
		t.Errorf("a clean verification needs no note, got %q", note)
	}
}

// TestVerifyTimestampImprint_ForeignToken is the attack the check exists for: a
// well-formed token that stamps a different signature.
func TestVerifyTimestampImprint_ForeignToken(t *testing.T) {
	other := sha256.Sum256([]byte("some other signature"))
	svc := New(&fakeProvider{})

	verified, note := svc.verifyTimestampImprint(context.Background(),
		signerWithToken([]byte("signature-value"), pki.DigestSHA256, other[:]))
	if verified == nil || *verified {
		t.Fatal("a token over another signature must not verify")
	}
	if !strings.Contains(note, "does not match") {
		t.Errorf("note = %q, want it to say the imprint does not match", note)
	}
}

// TestVerifyTimestampImprint_UnknownDigestIsUndetermined keeps "cannot tell"
// distinct from "does not match": hashing with a guessed algorithm would report
// a good timestamp as forged.
func TestVerifyTimestampImprint_UnknownDigestIsUndetermined(t *testing.T) {
	svc := New(&fakeProvider{})

	verified, note := svc.verifyTimestampImprint(context.Background(),
		signerWithToken([]byte("sig"), "1.3.36.3.2.1", []byte("imprint")))
	if verified != nil {
		t.Fatalf("an unsupported digest cannot yield a verdict, got %v", *verified)
	}
	if !strings.Contains(note, "unsupported") {
		t.Errorf("note = %q, want it to name the unsupported digest", note)
	}
}

// TestVerifyTimestampImprint_GOSTGoesThroughTheDriver pins where the GOST digest
// comes from: Go cannot compute it, so the imprint check depends on the library.
// For any GOST profile the TSP imprint is the older 34.311-95, which the driver
// does support.
func TestVerifyTimestampImprint_GOSTGoesThroughTheDriver(t *testing.T) {
	var asked provider.HashRequest
	prov := &fakeProvider{caps: provider.Capabilities{Hash: true}}
	prov.hashFunc = func(req provider.HashRequest) (provider.HashResult, error) {
		asked = req
		return provider.HashResult{Hash: []byte("gost-digest")}, nil
	}
	svc := New(prov)

	verified, note := svc.verifyTimestampImprint(context.Background(),
		signerWithToken([]byte("sig"), pki.DigestGOST34311_95, []byte("gost-digest")))
	if verified == nil || !*verified {
		t.Fatalf("the driver's digest must be accepted (note: %q)", note)
	}
	if asked.Algorithm != gostDigestName {
		t.Errorf("driver was asked for %q, want %q", asked.Algorithm, gostDigestName)
	}
}

// TestVerifyTimestampImprint_NoHashCapability covers a library build that cannot
// hash at all: the timestamp stays unverified rather than silently accepted.
func TestVerifyTimestampImprint_NoHashCapability(t *testing.T) {
	svc := New(&fakeProvider{})

	verified, note := svc.verifyTimestampImprint(context.Background(),
		signerWithToken([]byte("sig"), pki.DigestGOST34311_95, []byte("x")))
	if verified != nil {
		t.Fatal("without a hash capability there is no verdict to give")
	}
	if !strings.Contains(note, "cannot compute") {
		t.Errorf("note = %q, want it to say the library cannot compute the digest", note)
	}
}
