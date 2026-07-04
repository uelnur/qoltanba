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
	"google.golang.org/grpc/status"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
)

// Server implements the generated SignatureServiceServer over the domain service.
type Server struct {
	pb.UnimplementedSignatureServiceServer
	svc *core.Service
}

// New builds a gRPC server adapter.
func New(svc *core.Service) *Server { return &Server{svc: svc} }

// Register attaches the service to a grpc.ServiceRegistrar (the *grpc.Server).
func (s *Server) Register(reg grpclib.ServiceRegistrar) {
	pb.RegisterSignatureServiceServer(reg, s)
}

func (s *Server) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	out, err := s.svc.Sign(ctx, core.SignInput{
		Format: pbFormat(req.GetFormat()), Data: req.GetData(), Key: pbKeySpec(req.GetKey()),
		Detached: req.GetDetached(), WithTimestamp: req.WithTimestamp, TSAURL: req.GetTsaUrl(),
		NoCheckCertTime: req.GetNoCheckCertTime(), InputPEM: req.GetInputPem(), OutputPEM: req.GetOutputPem(),
		NodeID: req.GetNodeId(), ParentNode: req.GetParentNode(), ParentNS: req.GetParentNamespace(),
		ExistingSignature: req.GetExistingSignature(),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return &pb.SignResponse{
		Signature: out.Signature, Format: coreFormatPB(out.Format),
		Timestamp: timestampPB(out.Timestamp), CadesLevel: out.CAdESLevel, LibError: libErrorPB(out.LibError),
	}, nil
}

func (s *Server) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	out, err := s.svc.Verify(ctx, core.VerifyInput{
		Format: pbFormat(req.GetFormat()), Signature: req.GetSignature(), Data: req.GetData(),
		Detached: req.GetDetached(), InputPEM: req.GetInputPem(), CheckCertTime: req.GetCheckCertTime(),
		ExtractContent: req.GetExtractContent(), TrustedCerts: pbTrusted(req.GetTrustedCerts()),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return &pb.VerifyResponse{
		Valid: out.Valid, Format: coreFormatPB(out.Format), Detached: out.Detached,
		Signers: signersPB(out.Signers), Content: out.Content,
		Warnings: warningsPB(out.Warnings), LibError: libErrorPB(out.LibError),
	}, nil
}

func (s *Server) Extract(ctx context.Context, req *pb.ExtractRequest) (*pb.ExtractResponse, error) {
	out, err := s.svc.Extract(ctx, core.ExtractInput{
		Format: pbFormat(req.GetFormat()), Signature: req.GetSignature(), Data: req.GetData(),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return &pb.ExtractResponse{Content: out.Content, Detached: out.Detached, LibError: libErrorPB(out.LibError)}, nil
}

func (s *Server) CertInfo(ctx context.Context, req *pb.CertInfoRequest) (*pb.CertInfoResponse, error) {
	out, err := s.svc.CertInfo(ctx, core.CertInfoInput{
		Cert: req.GetCert(), Key: pbKeySpec(req.GetKey()), Format: pbEncoding(req.GetEncoding()),
		BuildChain: req.GetBuildChain(), Validate: req.GetValidate(), Method: pbMethod(req.GetMethod()),
		TrustedCerts: pbTrusted(req.GetTrustedCerts()),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return &pb.CertInfoResponse{
		Certificate: certPB(out.Certificate), Chain: certsPB(out.Chain),
		Warnings: warningsPB(out.Warnings), LibError: libErrorPB(out.LibError),
	}, nil
}

func (s *Server) CertValidate(ctx context.Context, req *pb.CertValidateRequest) (*pb.CertValidateResponse, error) {
	out, err := s.svc.Validate(ctx, core.ValidateInput{
		Cert: req.GetCert(), Format: pbEncoding(req.GetEncoding()), Method: pbMethod(req.GetMethod()),
		WantOCSP: req.GetWantOcsp(), ResponderURL: req.GetResponderUrl(), CRL: req.GetCrl(),
		TrustedCerts: pbTrusted(req.GetTrustedCerts()),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return &pb.CertValidateResponse{
		Status: revocationPB(out.Status), Info: out.Info, OcspResponse: out.OCSPResponse,
		Warnings: warningsPB(out.Warnings), LibError: libErrorPB(out.LibError),
	}, nil
}

// grpcError maps a domain error's kind to a gRPC status code.
func grpcError(err error) error {
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
	return status.Error(code, err.Error())
}
