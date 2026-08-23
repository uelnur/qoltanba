package core

import (
	"context"
	"testing"
	"time"

	"github.com/uelnur/qoltanba/internal/provider"
)

// TestVerifyRegistry_Summarizes covers the counts an auditor reads first and the
// per-row detail they act on.
func TestVerifyRegistry_Summarizes(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	root := makeCert(t, "Root", nil, true)
	leaf := makeCert(t, "Leaf", &root, false)
	// One provider driving three outcomes by input: a clean signature, a rejected
	// one, and an item the library cannot process at all.
	certFields := fields(map[string]string{
		"SUBJECT_COMMONNAME":   "ТЕСТОВ ТЕСТ",
		"SUBJECT_SERIALNUMBER": "IIN123456789011",
		"NOTBEFORE":            "01.01.2021 00:00:00 +00:00",
		"NOTAFTER":             "01.01.2030 00:00:00 +00:00",
	})
	prov := &fakeProvider{props: certFields,
		// The register asks the same questions a verify does, revocation included:
		// without an answer here every row would be indeterminate.
		validateResult: provider.ValidateResult{Status: provider.StatusGood},
		verifyFunc: func(req provider.VerifyRequest) (provider.VerifyResult, error) {
			switch string(req.Signature) {
			case "a":
				return provider.VerifyResult{Valid: true, Signers: [][]byte{leaf.pem}}, nil
			case "b":
				return provider.VerifyResult{Valid: false}, nil
			default:
				return provider.VerifyResult{}, provider.ErrCMSFormat
			}
		}}
	svc := New(prov, WithTrustStore(staticTrust{[]TrustedCert{{Cert: root.pem}}}),
		WithClock(func() time.Time { return now }))

	out := svc.VerifyRegistry(context.Background(), []RegistryItem{
		{Ref: "doc-1.p7s", Verify: VerifyInput{Format: FormatCMS, Signature: []byte("a")}},
		{Ref: "doc-2.p7s", Verify: VerifyInput{Format: FormatCMS, Signature: []byte("b")}},
		{Ref: "doc-3.p7s", Verify: VerifyInput{Format: FormatCMS, Signature: []byte("c")}},
	}, BatchOptions{})

	if out.Total != 3 || len(out.Rows) != 3 {
		t.Fatalf("total = %d, rows = %d, want 3/3", out.Total, len(out.Rows))
	}
	if out.Valid != 1 || out.Invalid != 1 || out.Failed != 1 {
		t.Errorf("counts = valid %d, invalid %d, indeterminate %d, failed %d",
			out.Valid, out.Invalid, out.Indeterminate, out.Failed)
	}
	if out.Rows[0].Ref != "doc-1.p7s" || out.Rows[0].Verdict != VerdictValid {
		t.Errorf("row 0 = %+v", out.Rows[0])
	}
	if len(out.Rows[0].Signers) != 1 || out.Rows[0].Signers[0].IIN != "123456789011" {
		t.Errorf("signer identity missing in the register: %+v", out.Rows[0].Signers)
	}
	if out.Rows[1].Verdict != VerdictInvalid || out.Rows[1].Reason == "" {
		t.Errorf("an invalid row must name its cause: %+v", out.Rows[1])
	}
	if out.Rows[2].Error == nil || out.Rows[2].Verdict != VerdictIndeterminate {
		t.Errorf("a failed item must carry its error, not a verdict: %+v", out.Rows[2])
	}
}

// TestVerifyRegistry_ForcesReport pins that the register does not depend on the
// caller remembering to ask for the report it is built from.
func TestVerifyRegistry_ForcesReport(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	root := makeCert(t, "Root", nil, true)
	leaf := makeCert(t, "Leaf", &root, false)
	prov := &fakeProvider{
		props: fields(map[string]string{
			"SUBJECT_COMMONNAME": "Leaf",
			"NOTBEFORE":          "01.01.2021 00:00:00 +00:00",
			"NOTAFTER":           "01.01.2030 00:00:00 +00:00",
		}),
		verifyResult: provider.VerifyResult{Valid: true, Signers: [][]byte{leaf.pem}},
	}
	svc := New(prov, WithTrustStore(staticTrust{[]TrustedCert{{Cert: root.pem}}}),
		WithClock(func() time.Time { return now }))

	out := svc.VerifyRegistry(context.Background(), []RegistryItem{
		{Verify: VerifyInput{Format: FormatCMS, Signature: []byte("a")}}, // Report not set
	}, BatchOptions{})

	if len(out.Rows) != 1 || out.Rows[0].Verdict == "" || out.Rows[0].Summary == "" {
		t.Fatalf("register row was not built: %+v", out.Rows)
	}
}
