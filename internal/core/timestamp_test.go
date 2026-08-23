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

// The policy is the operator's rule, not a fact the service can derive: every
// NUC policy chains to the same anchors, so the difference between them is which
// algorithms an operator is willing to rely on.

func TestTimestampPolicy_UnconfiguredEnforcesNothing(t *testing.T) {
	svc := New(&fakeProvider{})

	name, accepted, note := svc.checkTimestampPolicy(pki.TSAPolicyGOST2015)
	if name != "TSA_GOST2015_POLICY" {
		t.Errorf("name = %q, want the registry name", name)
	}
	if accepted != nil {
		t.Errorf("without an allow-list there is no verdict to give, got %v", *accepted)
	}
	if note == "" {
		t.Error("the absence of enforcement should be stated, not silent")
	}
}

func TestTimestampPolicy_AllowListAccepts(t *testing.T) {
	svc := New(&fakeProvider{}, WithTSAPolicies([]string{pki.TSAPolicyGOST2015}))

	_, accepted, note := svc.checkTimestampPolicy(pki.TSAPolicyGOST2015)
	if accepted == nil || !*accepted {
		t.Fatalf("the configured policy must be accepted (note %q)", note)
	}
}

func TestTimestampPolicy_AllowListRefusesOthers(t *testing.T) {
	// An operator requiring GOST-2015 does not want a token issued under the
	// older RSA policy to pass as CAdES-T.
	svc := New(&fakeProvider{}, WithTSAPolicies([]string{pki.TSAPolicyGOST2015}))

	_, accepted, note := svc.checkTimestampPolicy(pki.TSAPolicyRSA)
	if accepted == nil || *accepted {
		t.Fatal("a policy outside the allow-list must be refused")
	}
	if !strings.Contains(note, "TSA_RSA_POLICY") {
		t.Errorf("note = %q, want it to name the refused policy", note)
	}
}

func TestTimestampPolicy_UnknownOIDIsNamedByItsOID(t *testing.T) {
	svc := New(&fakeProvider{}, WithTSAPolicies([]string{pki.TSAPolicyGOST2015}))

	name, accepted, note := svc.checkTimestampPolicy("1.3.6.1.4.1.99999.1")
	if name != "" {
		t.Errorf("an OID outside the registry has no name, got %q", name)
	}
	if accepted == nil || *accepted {
		t.Fatal("an unknown policy must be refused when a list is configured")
	}
	if !strings.Contains(note, "1.3.6.1.4.1.99999.1") {
		t.Errorf("note = %q, want the bare OID when there is no name", note)
	}
}
