package grpc

import (
	"context"

	grpclib "google.golang.org/grpc"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/core"
)

// streamBatch runs a batch and streams one event per completed item (in
// completion order, tagged with its index) followed by a summary event. runBatch
// serializes the sink, so stream.Send is never called concurrently. A send error
// aborts the stream.
func streamBatch[In, Out, Ev any](
	stream grpclib.ServerStreamingServer[Ev],
	items []In,
	opts core.BatchOptions,
	run func(ctx context.Context, items []In, opts core.BatchOptions, sink func(core.BatchItem[Out])) core.BatchOutput[Out],
	itemEvent func(core.BatchItem[Out]) *Ev,
	summaryEvent func(core.BatchOutput[Out]) *Ev,
) error {
	var sendErr error
	out := run(stream.Context(), items, opts, func(bi core.BatchItem[Out]) {
		if sendErr != nil {
			return
		}
		if err := stream.Send(itemEvent(bi)); err != nil {
			sendErr = err
		}
	})
	if sendErr != nil {
		return sendErr
	}
	return stream.Send(summaryEvent(out))
}

// batchSummary builds the summary payload shared by every event type.
func batchSummary[T any](out core.BatchOutput[T]) *pb.BatchSummary {
	return &pb.BatchSummary{Total: int32(out.Total), Succeeded: int32(out.Succeeded), Failed: int32(out.Failed)}
}

func (s *Server) SignBatch(req *pb.SignBatchRequest, stream grpclib.ServerStreamingServer[pb.SignBatchEvent]) error {
	items := make([]core.SignInput, len(req.GetItems()))
	for i, it := range req.GetItems() {
		items[i] = signInputPB(it)
	}
	return streamBatch(stream, items, batchOptsPB(req.GetPolicy(), req.GetConcurrency()), s.svc.SignBatch,
		func(bi core.BatchItem[core.SignOutput]) *pb.SignBatchEvent {
			return &pb.SignBatchEvent{Event: &pb.SignBatchEvent_Item{Item: &pb.SignBatchItem{
				Index: int32(bi.Index), Status: string(bi.Status),
				Output: signResponsePB(bi.Output), Error: batchItemErrorPB(bi.Error),
			}}}
		},
		func(out core.BatchOutput[core.SignOutput]) *pb.SignBatchEvent {
			return &pb.SignBatchEvent{Event: &pb.SignBatchEvent_Summary{Summary: batchSummary(out)}}
		})
}

func (s *Server) VerifyBatch(req *pb.VerifyBatchRequest, stream grpclib.ServerStreamingServer[pb.VerifyBatchEvent]) error {
	items := make([]core.VerifyInput, len(req.GetItems()))
	for i, it := range req.GetItems() {
		items[i] = verifyInputPB(it)
	}
	return streamBatch(stream, items, batchOptsPB(req.GetPolicy(), req.GetConcurrency()), s.svc.VerifyBatch,
		func(bi core.BatchItem[core.VerifyOutput]) *pb.VerifyBatchEvent {
			return &pb.VerifyBatchEvent{Event: &pb.VerifyBatchEvent_Item{Item: &pb.VerifyBatchItem{
				Index: int32(bi.Index), Status: string(bi.Status),
				Output: verifyResponsePB(bi.Output), Error: batchItemErrorPB(bi.Error),
			}}}
		},
		func(out core.BatchOutput[core.VerifyOutput]) *pb.VerifyBatchEvent {
			return &pb.VerifyBatchEvent{Event: &pb.VerifyBatchEvent_Summary{Summary: batchSummary(out)}}
		})
}

func (s *Server) ExtractBatch(req *pb.ExtractBatchRequest, stream grpclib.ServerStreamingServer[pb.ExtractBatchEvent]) error {
	items := make([]core.ExtractInput, len(req.GetItems()))
	for i, it := range req.GetItems() {
		items[i] = extractInputPB(it)
	}
	return streamBatch(stream, items, batchOptsPB(req.GetPolicy(), req.GetConcurrency()), s.svc.ExtractBatch,
		func(bi core.BatchItem[core.ExtractOutput]) *pb.ExtractBatchEvent {
			return &pb.ExtractBatchEvent{Event: &pb.ExtractBatchEvent_Item{Item: &pb.ExtractBatchItem{
				Index: int32(bi.Index), Status: string(bi.Status),
				Output: extractResponsePB(bi.Output), Error: batchItemErrorPB(bi.Error),
			}}}
		},
		func(out core.BatchOutput[core.ExtractOutput]) *pb.ExtractBatchEvent {
			return &pb.ExtractBatchEvent{Event: &pb.ExtractBatchEvent_Summary{Summary: batchSummary(out)}}
		})
}

func (s *Server) CertInfoBatch(req *pb.CertInfoBatchRequest, stream grpclib.ServerStreamingServer[pb.CertInfoBatchEvent]) error {
	items := make([]core.CertInfoInput, len(req.GetItems()))
	for i, it := range req.GetItems() {
		items[i] = certInfoInputPB(it)
	}
	return streamBatch(stream, items, batchOptsPB(req.GetPolicy(), req.GetConcurrency()), s.svc.CertInfoBatch,
		func(bi core.BatchItem[core.CertInfoOutput]) *pb.CertInfoBatchEvent {
			return &pb.CertInfoBatchEvent{Event: &pb.CertInfoBatchEvent_Item{Item: &pb.CertInfoBatchItem{
				Index: int32(bi.Index), Status: string(bi.Status),
				Output: certInfoResponsePB(bi.Output), Error: batchItemErrorPB(bi.Error),
			}}}
		},
		func(out core.BatchOutput[core.CertInfoOutput]) *pb.CertInfoBatchEvent {
			return &pb.CertInfoBatchEvent{Event: &pb.CertInfoBatchEvent_Summary{Summary: batchSummary(out)}}
		})
}

func (s *Server) CertValidateBatch(req *pb.CertValidateBatchRequest, stream grpclib.ServerStreamingServer[pb.CertValidateBatchEvent]) error {
	items := make([]core.ValidateInput, len(req.GetItems()))
	for i, it := range req.GetItems() {
		items[i] = validateInputPB(it)
	}
	return streamBatch(stream, items, batchOptsPB(req.GetPolicy(), req.GetConcurrency()), s.svc.ValidateBatch,
		func(bi core.BatchItem[core.ValidateOutput]) *pb.CertValidateBatchEvent {
			return &pb.CertValidateBatchEvent{Event: &pb.CertValidateBatchEvent_Item{Item: &pb.CertValidateBatchItem{
				Index: int32(bi.Index), Status: string(bi.Status),
				Output: certValidateResponsePB(bi.Output), Error: batchItemErrorPB(bi.Error),
			}}}
		},
		func(out core.BatchOutput[core.ValidateOutput]) *pb.CertValidateBatchEvent {
			return &pb.CertValidateBatchEvent{Event: &pb.CertValidateBatchEvent_Summary{Summary: batchSummary(out)}}
		})
}
