package grpc

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/provider/fake"
)

// Archiving was reachable over REST, CLI, socket and MQ but not gRPC, so a gRPC
// consumer had no way to produce a long-term-verifiable container. These cover
// the transport's own job: carrying the request across and translating a domain
// refusal into a status code.

func TestGRPC_ArchiveRefusesEmptySignature(t *testing.T) {
	client := dial(t, core.New(&fake.Provider{}))

	_, err := client.Archive(context.Background(), &pb.ArchiveRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v (err %v), want InvalidArgument", status.Code(err), err)
	}
}

// TestArchiveInputMapping pins the fields that change what gets archived —
// especially allowRevoked, where losing the flag in transit would silently turn a
// deliberate override back into a refusal.
func TestArchiveInputMapping(t *testing.T) {
	in := archiveInputPB(&pb.ArchiveRequest{
		Signature: []byte("sig"), InputPem: true, Data: []byte("doc"), Detached: true,
		ResponderUrl: "http://ocsp.example", OutputPem: true, AllowRevoked: true,
		TrustedCerts: []*pb.TrustedCert{{Cert: []byte("ca"), Intermediate: true}},
	})

	if string(in.Signature) != "sig" || !in.InputPEM || string(in.Data) != "doc" || !in.Detached {
		t.Errorf("container fields lost: %+v", in)
	}
	if in.ResponderURL != "http://ocsp.example" || !in.OutputPEM || !in.AllowRevoked {
		t.Errorf("options lost: %+v", in)
	}
	if len(in.TrustedCerts) != 1 || !in.TrustedCerts[0].Intermediate {
		t.Errorf("anchors lost: %+v", in.TrustedCerts)
	}
}

func TestArchiveResponseMapping(t *testing.T) {
	out := archiveResponsePB(&core.ArchiveOutput{
		Signature: []byte("archived"), Level: "LT",
		Embedded: core.ArchiveEvidence{OCSPResponses: 1, CRLs: 2, Certificates: 3},
		Warnings: []core.Warning{{Field: "signers[0].revocation", Reason: "no reusable response"}},
	})

	if string(out.GetSignature()) != "archived" || out.GetLevel() != "LT" {
		t.Errorf("container lost: %+v", out)
	}
	e := out.GetEmbedded()
	if e.GetOcspResponses() != 1 || e.GetCrls() != 2 || e.GetCertificates() != 3 {
		t.Errorf("evidence counts lost: %+v", e)
	}
	// A thinner archive than asked for is reported, not silently shipped.
	if len(out.GetWarnings()) != 1 {
		t.Errorf("warnings lost: %+v", out.GetWarnings())
	}
}
