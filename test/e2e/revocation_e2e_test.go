//go:build qoltanba_functional

package e2e

import (
	"context"
	"os"
	"testing"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/keysource"
)

func TestFunctionalE2E_OCSPStructured(t *testing.T) {
	pool := requirePool(t)
	svc := core.New(pool,
		core.WithKeySource(keysource.New(keysource.WithInline(true))),
		core.WithTrustStore(loadEnvTrust(t)),
	)

	// Export the owner certificate, then validate it via OCSP.
	info, err := svc.CertInfo(context.Background(), core.CertInfoInput{Key: testKey(t)})
	if err != nil {
		t.Fatalf("cert info: %v", err)
	}
	out, err := svc.Validate(context.Background(), core.ValidateInput{
		Cert: info.Certificate.PEM, Format: core.EncodingPEM, Method: core.MethodOCSP,
		ResponderURL: os.Getenv("QOLTANBA_OCSP_URL"), WantOCSP: true,
	})
	if err != nil {
		t.Fatalf("ocsp validate: %v", err)
	}
	t.Logf("OCSP: revoked=%v reason=%q thisUpdate=%v nextUpdate=%v producedAt=%v respBytes=%d",
		out.Status.Revoked, out.Status.Reason, out.Status.ThisUpdate, out.Status.NextUpdate,
		out.Status.ProducedAt, len(out.OCSPResponse))
	if out.Status.CheckedAt == nil {
		t.Error("expected CheckedAt set")
	}
}

// TestFunctionalE2E_RevokedViaOCSP validates the revoked test key through the
// service and asserts the OCSP leg reports it revoked (the CRL leg is covered by
// the driver-level TestFunctional_Revocation).
func TestFunctionalE2E_RevokedViaOCSP(t *testing.T) {
	ocspURL := os.Getenv("QOLTANBA_OCSP_URL")
	if ocspURL == "" {
		t.Skip("QOLTANBA_OCSP_URL not set")
	}
	pool := requirePool(t)
	svc := core.New(pool,
		core.WithKeySource(keysource.New(keysource.WithInline(true))),
		core.WithTrustStore(loadEnvTrust(t)),
	)

	info, err := svc.CertInfo(context.Background(), core.CertInfoInput{Key: keyFromEnv(t, "QOLTANBA_KEY_REVOKED")})
	if err != nil {
		t.Fatalf("cert info (revoked): %v", err)
	}
	out, err := svc.Validate(context.Background(), core.ValidateInput{
		Cert: info.Certificate.PEM, Format: core.EncodingPEM, Method: core.MethodOCSP,
		ResponderURL: ocspURL, WantOCSP: true,
	})
	if err != nil {
		t.Fatalf("ocsp validate: %v", err)
	}
	if !out.Status.Revoked {
		t.Errorf("expected revoked=true for the revoked key; status=%+v", out.Status)
	}
	t.Logf("revoked key OCSP: revoked=%v reason=%q", out.Status.Revoked, out.Status.Reason)
}

// TestFunctionalE2E_BatchValidateRevocation validates a valid and a revoked cert
// in one batch via OCSP: real revocation through the batch surface.
func TestFunctionalE2E_BatchValidateRevocation(t *testing.T) {
	ocspURL := os.Getenv("QOLTANBA_OCSP_URL")
	if ocspURL == "" {
		t.Skip("QOLTANBA_OCSP_URL not set")
	}
	svc, closer := newService(t)
	defer closer()

	validInfo, err := svc.CertInfo(context.Background(), core.CertInfoInput{Key: testKey(t)})
	if err != nil {
		t.Fatalf("cert info (valid): %v", err)
	}
	revokedInfo, err := svc.CertInfo(context.Background(), core.CertInfoInput{Key: keyFromEnv(t, "QOLTANBA_KEY_REVOKED")})
	if err != nil {
		t.Fatalf("cert info (revoked): %v", err)
	}

	out := svc.ValidateBatch(context.Background(), []core.ValidateInput{
		{Cert: validInfo.Certificate.PEM, Format: core.EncodingPEM, Method: core.MethodOCSP, ResponderURL: ocspURL},
		{Cert: revokedInfo.Certificate.PEM, Format: core.EncodingPEM, Method: core.MethodOCSP, ResponderURL: ocspURL},
	}, core.BatchOptions{}, nil)

	if out.Total != 2 {
		t.Fatalf("total = %d, want 2", out.Total)
	}
	valid, revoked := out.Results[0].Output, out.Results[1].Output
	if valid == nil || revoked == nil {
		t.Fatalf("missing batch outputs: %+v", out.Results)
	}
	// An unreachable responder surfaces as a soft LibError with revoked=false;
	// skip rather than fail so an offline run does not report a false negative.
	if !revoked.Status.Revoked && revoked.Status.LibError != nil {
		t.Skipf("OCSP responder unreachable — cannot confirm revocation (libError=%s)", revoked.Status.LibError.Code)
	}
	if valid.Status.Revoked {
		t.Errorf("valid cert reported revoked")
	}
	if !revoked.Status.Revoked {
		t.Errorf("revoked cert not reported revoked; status=%+v", revoked.Status)
	}
	t.Logf("batch OCSP: valid.revoked=%v revoked.revoked=%v", valid.Status.Revoked, revoked.Status.Revoked)
}
