package core

import (
	"context"
	"strings"
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
)

// Archiving asserts something about a signature — that it was worth preserving.
// These pin the two cases where that assertion would be false: a signature that
// does not verify, and one whose signer has been repudiated. Both used to come
// back as a successful archive at level LT.

func TestArchiveRefusesRevokedSigner(t *testing.T) {
	_, svc := revocationFixture(t, provider.StatusRevoked)

	_, err := svc.Archive(context.Background(), ArchiveInput{Signature: buildTestCMS(t)})
	if err == nil {
		t.Fatal("archiving a revoked signature must not report success")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("the refusal must name the cause: %v", err)
	}
}

// TestArchiveAllowsRevokedOnRequest keeps the deliberate case possible: proof
// about a signature made before its certificate was revoked is worth preserving,
// as long as the caller says so.
func TestArchiveAllowsRevokedOnRequest(t *testing.T) {
	prov, svc := revocationFixture(t, provider.StatusRevoked)
	prov.validateResult.OCSPResponse = []byte("ocsp-response")

	out, err := svc.Archive(context.Background(), ArchiveInput{
		Signature: buildTestCMS(t), AllowRevoked: true,
	})
	if err != nil {
		t.Fatalf("archive with allowRevoked: %v", err)
	}
	if out.Embedded.OCSPResponses != 1 {
		t.Errorf("the revoked responder answer is the evidence worth keeping: %+v", out.Embedded)
	}
}

func TestArchiveRefusesUnverifiableContainer(t *testing.T) {
	prov, svc := revocationFixture(t, provider.StatusGood)
	prov.verifyResult = provider.VerifyResult{Valid: false, Signers: prov.verifyResult.Signers}

	_, err := svc.Archive(context.Background(), ArchiveInput{Signature: buildTestCMS(t)})
	if err == nil {
		t.Fatal("archiving a container that does not verify must not report success")
	}
	if !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("the refusal must name the cause: %v", err)
	}
}

// TestVerifyArchiveReusesTheSameEvidence is the point of folding archiving into
// verify: one responder round trip serves both the verdict and the archive, so
// the evidence filed is the evidence the verdict was reached on.
func TestVerifyArchiveReusesTheSameEvidence(t *testing.T) {
	prov, svc := revocationFixture(t, provider.StatusGood)
	prov.validateResult.OCSPResponse = []byte("ocsp-response")

	out, err := svc.Verify(context.Background(), VerifyInput{
		Format: FormatCMS, Signature: buildTestCMS(t), Archive: true,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.Archive == nil {
		t.Fatal("the archived container must come back with the verification")
	}
	if out.Archive.Embedded.OCSPResponses != 1 || out.Archive.Level != "LT" {
		t.Errorf("embedded = %+v, level = %q", out.Archive.Embedded, out.Archive.Level)
	}
	if prov.validateCalls != 1 {
		t.Errorf("responder was asked %d times; verifying and archiving should share one answer", prov.validateCalls)
	}
}
