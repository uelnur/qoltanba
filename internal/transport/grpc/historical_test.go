package grpc

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
)

func TestVerifyAtOverGRPC(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour).UTC()
	prov := &fake.Provider{
		VerifyResult: provider.VerifyResult{
			Valid:   true,
			Signers: [][]byte{[]byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")},
		},
		Props: fake.Fields(map[string]string{
			"SUBJECT_COMMONNAME": "ТЕСТОВ ТЕСТ",
			"NOTBEFORE":          "01.01.2021 00:00:00 +00:00",
			"NOTAFTER":           "01.01.2030 00:00:00 +00:00",
		}),
	}
	s := New(core.New(prov))

	out, err := s.VerifyAt(context.Background(), &pb.VerifyAtRequest{
		Verify: &pb.VerifyRequest{Format: pb.SignatureFormat_CMS, Signature: []byte("sig")},
		At:     past.Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("VerifyAt: %v", err)
	}
	if out.GetAt() == "" || len(out.GetSigners()) != 1 {
		t.Fatalf("response = %+v", out)
	}
	v := out.GetSigners()[0].GetVerdict()
	if !v.GetWithinValidity() || v.GetAt() == "" {
		t.Errorf("verdict = %+v", v)
	}
}

// TestVerifyAtRejectsABadInstant keeps a malformed time a client fault rather
// than a server error.
func TestVerifyAtRejectsABadInstant(t *testing.T) {
	s := New(core.New(&fake.Provider{}))

	_, err := s.VerifyAt(context.Background(), &pb.VerifyAtRequest{
		Verify: &pb.VerifyRequest{Signature: []byte("sig")},
		At:     "yesterday",
	})
	if err == nil {
		t.Fatal("a malformed instant must be rejected")
	}
	if !strings.Contains(err.Error(), "RFC3339") && !strings.Contains(err.Error(), "at ") {
		t.Errorf("err = %v, want it to name the expected format", err)
	}
}
