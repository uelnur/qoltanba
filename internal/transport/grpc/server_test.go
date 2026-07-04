package grpc

import (
	"context"
	"net"
	"testing"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
)

func dial(t *testing.T, svc *core.Service) pb.SignatureServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpclib.NewServer()
	New(svc).Register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpclib.NewClient("passthrough:///bufnet",
		grpclib.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpclib.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewSignatureServiceClient(conn)
}

func TestGRPC_Verify(t *testing.T) {
	f := &fake.Provider{
		VerifyResult: provider.VerifyResult{
			Valid:   true,
			Signers: [][]byte{[]byte("-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----")},
		},
		Props: fake.Fields(map[string]string{"SUBJECT_COMMONNAME": "ТЕСТ", "SUBJECT_SERIALNUMBER": "IIN900130300123"}),
	}
	client := dial(t, core.New(f))

	resp, err := client.Verify(context.Background(), &pb.VerifyRequest{
		Format: pb.SignatureFormat_CMS, Signature: []byte("sig"),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !resp.GetValid() || len(resp.GetSigners()) != 1 {
		t.Fatalf("unexpected response %+v", resp)
	}
	if got := resp.GetSigners()[0].GetCertificate().GetSubject().GetIin(); got != "900130300123" {
		t.Errorf("signer IIN = %q", got)
	}
}

func TestGRPC_SignVerifyOnlyIsInvalidArgument(t *testing.T) {
	client := dial(t, core.New(&fake.Provider{}, core.WithVerifyOnly(true)))
	_, err := client.Sign(context.Background(), &pb.SignRequest{
		Format: pb.SignatureFormat_CMS, Data: []byte("x"),
		Key: &pb.KeySpec{Source: &pb.KeySpec_Path{Path: &pb.PathKey{Path: "/k.p12"}}},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestGRPC_BadFormat(t *testing.T) {
	client := dial(t, core.New(&fake.Provider{}))
	_, err := client.Verify(context.Background(), &pb.VerifyRequest{
		Format: pb.SignatureFormat_SIGNATURE_FORMAT_UNSPECIFIED, Signature: []byte("x"),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}
