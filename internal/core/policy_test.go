package core

import (
	"context"
	"strings"
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
)

func TestApplyPolicy(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name       string
		in         SignInput
		wantFormat SignatureFormat
		wantStamp  *bool
		wantErr    string
	}{
		{"cades-b resolves to CMS without a stamp", SignInput{Policy: PolicyCAdESB}, FormatCMS, &no, ""},
		{"cades-t resolves to CMS with a stamp", SignInput{Policy: PolicyCAdEST}, FormatCMS, &yes, ""},
		{"xades-t resolves to XML with a stamp", SignInput{Policy: PolicyXAdEST}, FormatXML, &yes, ""},
		{"no policy leaves the request alone", SignInput{Format: FormatWSSE}, FormatWSSE, nil, ""},
		{"unknown policy is refused", SignInput{Policy: "cades-lta"}, "", nil, "unknown signature policy"},
		{"contradicting format is refused", SignInput{Policy: PolicyCAdESB, Format: FormatXML}, "", nil, "signs cms"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			err := applyPolicy(&in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("applyPolicy: %v", err)
			}
			if in.Format != tc.wantFormat {
				t.Errorf("format = %q, want %q", in.Format, tc.wantFormat)
			}
			switch {
			case tc.wantStamp == nil && in.WithTimestamp != nil:
				t.Errorf("withTimestamp = %v, want it untouched", *in.WithTimestamp)
			case tc.wantStamp != nil && (in.WithTimestamp == nil || *in.WithTimestamp != *tc.wantStamp):
				t.Errorf("withTimestamp = %v, want %v", in.WithTimestamp, *tc.wantStamp)
			}
		})
	}
}

// TestApplyPolicy_ExplicitTimestampWins keeps the level a default, not a cage: a
// caller who explicitly asks for no stamp under cades-t gets what they asked for
// (and the resulting cadesLevel will say BES).
func TestApplyPolicy_ExplicitTimestampWins(t *testing.T) {
	no := false
	in := SignInput{Policy: PolicyCAdEST, WithTimestamp: &no}
	if err := applyPolicy(&in); err != nil {
		t.Fatalf("applyPolicy: %v", err)
	}
	if in.WithTimestamp == nil || *in.WithTimestamp {
		t.Errorf("withTimestamp = %v, want the caller's explicit false", in.WithTimestamp)
	}
}

func TestSign_PolicyReachesTheDriver(t *testing.T) {
	prov := &fakeProvider{
		caps:       provider.Capabilities{SignCMS: true, Timestamp: true},
		signResult: provider.SignResult{Signature: []byte("sig")},
	}
	svc := New(prov, WithKeySource(staticKeySource{}))

	if _, err := svc.Sign(context.Background(), SignInput{
		Policy: PolicyCAdEST, Data: []byte("d"), Key: KeySpec{Path: &PathKey{Path: "/k.p12"}},
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if prov.lastSignCMS == nil {
		t.Fatal("policy did not resolve to a CMS signature")
	}
	if !prov.lastSignCMS.WithTimestamp {
		t.Error("cades-t did not request a time-stamp")
	}
}

func TestSign_UnknownPolicyIsRejected(t *testing.T) {
	svc := New(&fakeProvider{caps: provider.Capabilities{SignCMS: true}}, WithKeySource(staticKeySource{}))
	_, err := svc.Sign(context.Background(), SignInput{Policy: "pades-b", Data: []byte("d"), Key: KeySpec{Path: &PathKey{Path: "/k.p12"}}})
	if err == nil || !strings.Contains(err.Error(), "unknown signature policy") {
		t.Fatalf("err = %v, want a rejected policy", err)
	}
}
