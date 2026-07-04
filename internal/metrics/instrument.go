package metrics

import (
	"context"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// InstrumentHTTP wraps next so each request is recorded under the given transport
// label. The op comes from the routed pattern (req.Pattern, populated by the mux
// after it matches); the outcome from the response status class. Returns next
// unchanged on a nil Recorder.
func (r *Recorder) InstrumentHTTP(transport string, next http.Handler) http.Handler {
	if r == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, req)
		r.Observe(transport, opFromPattern(req.Pattern), outcomeForStatus(sw.status), time.Since(start))
	})
}

// UnaryInterceptor records each gRPC unary call under the "grpc" transport. The
// op is the lowercased method name; the outcome is "ok" or the status code name.
// Returns a pass-through interceptor on a nil Recorder.
func (r *Recorder) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		if r != nil {
			r.Observe("grpc", opFromGRPCMethod(info.FullMethod), grpcOutcome(err), time.Since(start))
		}
		return resp, err
	}
}

// statusRecorder captures the response status code for outcome classification.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true // an implicit 200 if WriteHeader was not called
	return s.ResponseWriter.Write(b)
}

// outcomeForStatus classifies an HTTP status into an outcome label.
func outcomeForStatus(code int) string {
	switch {
	case code < 400:
		return "ok"
	case code < 500:
		return "client_error"
	default:
		return "server_error"
	}
}

// opFromGRPCMethod turns "/qoltanba.v1.SignatureService/CertValidate" into
// "certvalidate".
func opFromGRPCMethod(full string) string {
	if i := strings.LastIndexByte(full, '/'); i >= 0 {
		full = full[i+1:]
	}
	if full == "" {
		return "unknown"
	}
	return strings.ToLower(full)
}

// grpcOutcome maps a handler error to an outcome label.
func grpcOutcome(err error) string {
	if err == nil {
		return "ok"
	}
	return strings.ToLower(status.Code(err).String())
}
