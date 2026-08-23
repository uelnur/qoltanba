// Package grpc is the gRPC transport: a thin adapter mapping the generated
// protobuf messages to the domain's core inputs and back. Like the other
// transports it holds no crypto or driver logic. The contract lives in
// api/qoltanba/v1/service.proto (a focused, stable subset — not the draft
// api/native.proto).
package grpc

import (
	"context"
	"errors"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/jobs"
)

// Server implements the generated SignatureServiceServer over the domain service.
type Server struct {
	pb.UnimplementedSignatureServiceServer
	svc  *core.Service
	jobs *jobs.Manager // nil disables the job RPCs (they return Unimplemented)
}

// Option configures a Server.
type Option func(*Server)

// WithJobs enables the async-job RPCs backed by the given manager.
func WithJobs(m *jobs.Manager) Option { return func(s *Server) { s.jobs = m } }

// New builds a gRPC server adapter.
func New(svc *core.Service, opts ...Option) *Server {
	s := &Server{svc: svc}
	for _, o := range opts {
		o(s)
	}
	return s
}

// LocaleInterceptor renders error messages in the language the caller requests
// through the standard accept-language metadata key. Attach it with
// grpc.ChainUnaryInterceptor; without it every call renders English.
func LocaleInterceptor() grpclib.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpclib.UnaryServerInfo, handler grpclib.UnaryHandler) (any, error) {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if tags := md.Get("accept-language"); len(tags) > 0 && tags[0] != "" {
				ctx = core.ContextWithLocale(ctx, tags[0])
			}
		}
		return handler(ctx, req)
	}
}

// Register attaches the service to a grpc.ServiceRegistrar (the *grpc.Server).
func (s *Server) Register(reg grpclib.ServiceRegistrar) {
	pb.RegisterSignatureServiceServer(reg, s)
}

func (s *Server) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	out, err := s.svc.Sign(ctx, signInputPB(req))
	if err != nil {
		return nil, grpcError(ctx, err)
	}
	return signResponsePB(&out), nil
}

func (s *Server) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	out, err := s.svc.Verify(ctx, verifyInputPB(req))
	if err != nil {
		return nil, grpcError(ctx, err)
	}
	return verifyResponsePB(&out), nil
}

func (s *Server) Archive(ctx context.Context, req *pb.ArchiveRequest) (*pb.ArchiveResponse, error) {
	out, err := s.svc.Archive(ctx, archiveInputPB(req))
	if err != nil {
		return nil, grpcError(ctx, err)
	}
	return archiveResponsePB(&out), nil
}

func (s *Server) Extract(ctx context.Context, req *pb.ExtractRequest) (*pb.ExtractResponse, error) {
	out, err := s.svc.Extract(ctx, extractInputPB(req))
	if err != nil {
		return nil, grpcError(ctx, err)
	}
	return extractResponsePB(&out), nil
}

func (s *Server) CertInfo(ctx context.Context, req *pb.CertInfoRequest) (*pb.CertInfoResponse, error) {
	out, err := s.svc.CertInfo(ctx, certInfoInputPB(req))
	if err != nil {
		return nil, grpcError(ctx, err)
	}
	return certInfoResponsePB(&out), nil
}

func (s *Server) CertValidate(ctx context.Context, req *pb.CertValidateRequest) (*pb.CertValidateResponse, error) {
	out, err := s.svc.Validate(ctx, validateInputPB(req))
	if err != nil {
		return nil, grpcError(ctx, err)
	}
	return certValidateResponsePB(&out), nil
}

// grpcError maps a domain error's kind to a gRPC status code, using the friendly
// catalog message (with the suggested action appended) as the status message,
// rendered in the language the call asked for.
func grpcError(ctx context.Context, err error) error {
	code := codes.Internal
	var de *core.Error
	if errors.As(err, &de) {
		switch de.Kind {
		case core.KindInvalid:
			code = codes.InvalidArgument
		case core.KindUnsupported:
			code = codes.Unimplemented
		case core.KindUnavailable:
			code = codes.Unavailable
		case core.KindCanceled:
			code = codes.Canceled
		}
	}
	msg := err.Error()
	if exp := core.ExplainIn(ctx, err); exp.Message != "" {
		msg = exp.Message
		if exp.Action != "" {
			msg += " " + exp.Action
		}
	}
	return status.Error(code, msg)
}
