package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/jobs"
)

// jobsEnabled reports whether the async-job RPCs are available, returning an
// Unimplemented status when the manager was not wired.
func (s *Server) jobsEnabled() error {
	if s.jobs == nil {
		return status.Error(codes.Unimplemented, "async jobs are disabled on this server")
	}
	return nil
}

func (s *Server) SubmitJob(ctx context.Context, req *pb.SubmitJobRequest) (*pb.JobStatus, error) {
	if err := s.jobsEnabled(); err != nil {
		return nil, err
	}
	v, err := s.jobs.Submit(ctx, req.GetOp(), req.GetRequest(), req.GetCallbackUrl())
	if err != nil {
		return nil, jobGRPCError(err)
	}
	return jobStatusPB(v), nil
}

func (s *Server) GetJob(ctx context.Context, req *pb.JobId) (*pb.JobStatus, error) {
	if err := s.jobsEnabled(); err != nil {
		return nil, err
	}
	v, err := s.jobs.Get(ctx, req.GetId())
	if err != nil {
		return nil, jobGRPCError(err)
	}
	return jobStatusPB(v), nil
}

func (s *Server) GetJobResult(ctx context.Context, req *pb.JobId) (*pb.JobResult, error) {
	if err := s.jobsEnabled(); err != nil {
		return nil, err
	}
	raw, st, err := s.jobs.Result(ctx, req.GetId())
	if err != nil {
		return nil, jobGRPCError(err) // ErrNotReady → FailedPrecondition, keep polling
	}
	return &pb.JobResult{Status: string(st), Result: raw}, nil
}

func (s *Server) CancelJob(ctx context.Context, req *pb.JobId) (*pb.JobStatus, error) {
	if err := s.jobsEnabled(); err != nil {
		return nil, err
	}
	if err := s.jobs.Cancel(ctx, req.GetId()); err != nil {
		return nil, jobGRPCError(err)
	}
	v, err := s.jobs.Get(ctx, req.GetId())
	if err != nil {
		return nil, jobGRPCError(err)
	}
	return jobStatusPB(v), nil
}

// jobGRPCError maps a job manager error to a gRPC status code.
func jobGRPCError(err error) error {
	code := codes.Internal
	switch {
	case errors.Is(err, jobs.ErrNotFound):
		code = codes.NotFound
	case errors.Is(err, jobs.ErrInvalidOp):
		code = codes.InvalidArgument
	case errors.Is(err, jobs.ErrTooLarge):
		code = codes.ResourceExhausted
	case errors.Is(err, jobs.ErrBusy):
		code = codes.Unavailable
	case errors.Is(err, jobs.ErrNotReady):
		code = codes.FailedPrecondition
	}
	return status.Error(code, err.Error())
}
