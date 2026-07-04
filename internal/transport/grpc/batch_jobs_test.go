package grpc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/jobs"
	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
	"github.com/uelnur/qoltanba/internal/transport/dispatch"
)

// dialWithJobs is dial plus a wired async-job manager (executor over dispatch).
func dialWithJobs(t *testing.T, svc *core.Service) pb.SignatureServiceClient {
	t.Helper()
	exec := func(ctx context.Context, op string, req json.RawMessage) (any, error) {
		return dispatch.Handle(ctx, svc, op, req)
	}
	mgr := jobs.New(jobs.NewMemStore(), exec, dispatch.Valid, jobs.Config{Workers: 2})
	ctx, cancel := context.WithCancel(context.Background())
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { cancel(); mgr.Wait() })

	lis := bufconn.Listen(1 << 20)
	srv := grpclib.NewServer()
	New(svc, WithJobs(mgr)).Register(srv)
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

func TestGRPC_ValidateBatchStream(t *testing.T) {
	f := &fake.Provider{ValidateResult: provider.ValidateResult{Status: provider.StatusGood}}
	client := dial(t, core.New(f))

	stream, err := client.CertValidateBatch(context.Background(), &pb.CertValidateBatchRequest{
		Items: []*pb.CertValidateRequest{
			{Cert: []byte("a"), Encoding: pb.CertEncoding_DER},
			{Cert: []byte("b"), Encoding: pb.CertEncoding_DER},
			{Cert: []byte("c"), Encoding: pb.CertEncoding_DER},
		},
	})
	if err != nil {
		t.Fatalf("CertValidateBatch: %v", err)
	}
	var items, summaries int
	for {
		ev, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		switch ev.GetEvent().(type) {
		case *pb.CertValidateBatchEvent_Item:
			items++
		case *pb.CertValidateBatchEvent_Summary:
			summaries++
			if got := ev.GetSummary().GetTotal(); got != 3 {
				t.Errorf("summary total = %d, want 3", got)
			}
		}
	}
	if items != 3 || summaries != 1 {
		t.Fatalf("stream had %d items, %d summaries, want 3/1", items, summaries)
	}
}

func TestGRPC_JobLifecycle(t *testing.T) {
	f := &fake.Provider{ValidateResult: provider.ValidateResult{Status: provider.StatusGood}}
	client := dialWithJobs(t, core.New(f))
	ctx := context.Background()

	req, _ := json.Marshal(map[string]any{"cert": []byte("c"), "encoding": "der"})
	sub, err := client.SubmitJob(ctx, &pb.SubmitJobRequest{Op: "cert-validate", Request: req})
	if err != nil {
		t.Fatalf("SubmitJob: %v", err)
	}
	if sub.GetId() == "" {
		t.Fatal("no job id")
	}

	deadline := time.Now().Add(2 * time.Second)
	var st string
	for time.Now().Before(deadline) {
		js, err := client.GetJob(ctx, &pb.JobId{Id: sub.GetId()})
		if err != nil {
			t.Fatalf("GetJob: %v", err)
		}
		st = js.GetStatus()
		if st == "succeeded" || st == "failed" || st == "canceled" {
			break
		}
		time.Sleep(3 * time.Millisecond)
	}
	if st != "succeeded" {
		t.Fatalf("final status = %s, want succeeded", st)
	}

	res, err := client.GetJobResult(ctx, &pb.JobId{Id: sub.GetId()})
	if err != nil {
		t.Fatalf("GetJobResult: %v", err)
	}
	var out core.ValidateOutput
	if err := json.Unmarshal(res.GetResult(), &out); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if out.Status.Revoked {
		t.Errorf("unexpected revoked")
	}
}

func TestGRPC_JobsDisabledIsUnimplemented(t *testing.T) {
	client := dial(t, core.New(&fake.Provider{})) // no WithJobs
	_, err := client.SubmitJob(context.Background(), &pb.SubmitJobRequest{Op: "verify", Request: []byte("{}")})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented", status.Code(err))
	}
}

func TestGRPC_JobNotFound(t *testing.T) {
	client := dialWithJobs(t, core.New(&fake.Provider{}))
	_, err := client.GetJob(context.Background(), &pb.JobId{Id: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}
