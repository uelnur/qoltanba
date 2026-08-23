package grpc

import (
	"context"
	"time"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
)

// VerifyAt answers whether a signature was valid at a past instant. It brings the
// gRPC surface level with REST, which has had /verify/at since the feature landed.
func (s *Server) VerifyAt(ctx context.Context, req *pb.VerifyAtRequest) (*pb.VerifyAtResponse, error) {
	in, err := verifyAtInputPB(req)
	if err != nil {
		return nil, grpcError(ctx, err)
	}
	out, err := s.svc.VerifyAt(ctx, in)
	if err != nil {
		return nil, grpcError(ctx, err)
	}
	return verifyAtResponsePB(&out), nil
}

func verifyAtInputPB(req *pb.VerifyAtRequest) (core.VerifyAtInput, error) {
	at, err := time.Parse(time.RFC3339, req.GetAt())
	if err != nil {
		return core.VerifyAtInput{}, core.NewError(core.KindInvalid, "VerifyAt",
			"at must be an RFC3339 instant: "+err.Error())
	}
	return core.VerifyAtInput{
		VerifyInput:  verifyInputPB(req.GetVerify()),
		At:           at,
		Method:       pbMethod(req.GetMethod()),
		CRL:          req.GetCrl(),
		ResponderURL: req.GetResponderUrl(),
	}, nil
}

func verifyAtResponsePB(o *core.VerifyAtOutput) *pb.VerifyAtResponse {
	if o == nil {
		return nil
	}
	signers := make([]*pb.SignerAt, 0, len(o.Signers))
	for _, s := range o.Signers {
		signers = append(signers, &pb.SignerAt{
			Signer:  signerPB(s.Signer),
			Verdict: verdictPB(s.Verdict),
		})
	}
	return &pb.VerifyAtResponse{
		At: o.At.UTC().Format(time.RFC3339), ValidAt: o.ValidAt, Determinate: o.Determinate,
		Format: coreFormatPB(o.Format), Detached: o.Detached, Signers: signers,
		Warnings: warningsPB(o.Warnings), LibError: libErrorPB(o.LibError),
	}
}

func verdictPB(v core.PointInTimeVerdict) *pb.PointInTimeVerdict {
	return &pb.PointInTimeVerdict{
		At: v.At.UTC().Format(time.RFC3339), ValidAt: v.ValidAt, Determinate: v.Determinate,
		SignatureValid: v.SignatureValid, WithinValidity: v.WithinValidity,
		NotBefore: rfc3339(v.NotBefore), NotAfter: rfc3339(v.NotAfter),
		NotRevokedAt: v.NotRevokedAt, RevokedAsOfAt: v.RevokedAsOfAt,
		RevocationTime: rfc3339(v.RevocationTime), RevocationReason: v.RevocationReason,
		Method: coreMethodPB(v.Method), Reasons: v.Reasons,
	}
}
