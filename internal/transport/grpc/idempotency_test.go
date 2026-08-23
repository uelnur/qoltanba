package grpc

import (
	"context"
	"testing"
	"time"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/uelnur/qoltanba/api/qoltanba/v1"
	"github.com/uelnur/qoltanba/internal/idempotency"
)

func withKey(key string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(idempotencyKey, key))
}

// TestIdempotencyReplaysWithoutReExecuting is the whole point: a redelivery must
// return the first answer, not run the operation a second time.
func TestIdempotencyReplaysWithoutReExecuting(t *testing.T) {
	cache := idempotency.New(time.Minute, 16, nil)
	interceptor := IdempotencyInterceptor(cache)
	info := &grpclib.UnaryServerInfo{FullMethod: "/qoltanba.v1.SignatureService/Verify"}

	calls := 0
	handler := func(context.Context, any) (any, error) {
		calls++
		return &pb.VerifyResponse{Valid: true, Content: []byte("recovered")}, nil
	}

	first, err := interceptor(withKey("k1"), &pb.VerifyRequest{}, info, handler)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := interceptor(withKey("k1"), &pb.VerifyRequest{}, info, handler)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}

	if calls != 1 {
		t.Errorf("handler ran %d times, want 1", calls)
	}
	got, ok := second.(*pb.VerifyResponse)
	if !ok {
		t.Fatalf("replay returned %T", second)
	}
	if !got.GetValid() || string(got.GetContent()) != "recovered" {
		t.Errorf("replayed response = %+v, want the first one", got)
	}
	if first.(*pb.VerifyResponse).GetValid() != got.GetValid() {
		t.Error("replay differs from the original")
	}
}

func TestIdempotencyDistinguishesKeysAndMethods(t *testing.T) {
	cache := idempotency.New(time.Minute, 16, nil)
	interceptor := IdempotencyInterceptor(cache)

	calls := 0
	handler := func(context.Context, any) (any, error) {
		calls++
		return &pb.VerifyResponse{Valid: true}, nil
	}
	verify := &grpclib.UnaryServerInfo{FullMethod: "/qoltanba.v1.SignatureService/Verify"}
	extract := &grpclib.UnaryServerInfo{FullMethod: "/qoltanba.v1.SignatureService/Extract"}

	_, _ = interceptor(withKey("k1"), &pb.VerifyRequest{}, verify, handler)
	_, _ = interceptor(withKey("k2"), &pb.VerifyRequest{}, verify, handler)
	_, _ = interceptor(withKey("k1"), &pb.VerifyRequest{}, extract, handler)

	if calls != 3 {
		t.Errorf("handler ran %d times, want 3 (a key is scoped to its method)", calls)
	}
}

// TestIdempotencyDoesNotCacheFailures keeps a transient error from being pinned
// for the whole TTL.
func TestIdempotencyDoesNotCacheFailures(t *testing.T) {
	cache := idempotency.New(time.Minute, 16, nil)
	interceptor := IdempotencyInterceptor(cache)
	info := &grpclib.UnaryServerInfo{FullMethod: "/qoltanba.v1.SignatureService/Verify"}

	calls := 0
	handler := func(context.Context, any) (any, error) {
		calls++
		if calls == 1 {
			return nil, context.DeadlineExceeded
		}
		return &pb.VerifyResponse{Valid: true}, nil
	}

	if _, err := interceptor(withKey("k1"), &pb.VerifyRequest{}, info, handler); err == nil {
		t.Fatal("first call should fail")
	}
	out, err := interceptor(withKey("k1"), &pb.VerifyRequest{}, info, handler)
	if err != nil {
		t.Fatalf("retry after failure: %v", err)
	}
	if !out.(*pb.VerifyResponse).GetValid() || calls != 2 {
		t.Errorf("retry did not re-execute: calls = %d", calls)
	}
}

// TestIdempotencyPassesThroughWithoutKey keeps ordinary calls untouched.
func TestIdempotencyPassesThroughWithoutKey(t *testing.T) {
	interceptor := IdempotencyInterceptor(idempotency.New(time.Minute, 16, nil))
	info := &grpclib.UnaryServerInfo{FullMethod: "/qoltanba.v1.SignatureService/Verify"}

	calls := 0
	handler := func(context.Context, any) (any, error) {
		calls++
		return &pb.VerifyResponse{}, nil
	}
	_, _ = interceptor(context.Background(), &pb.VerifyRequest{}, info, handler)
	_, _ = interceptor(context.Background(), &pb.VerifyRequest{}, info, handler)

	if calls != 2 {
		t.Errorf("handler ran %d times, want 2 without a key", calls)
	}
}

func TestIdempotencyWithoutCacheIsPassThrough(t *testing.T) {
	interceptor := IdempotencyInterceptor(nil)
	info := &grpclib.UnaryServerInfo{FullMethod: "/qoltanba.v1.SignatureService/Verify"}
	calls := 0
	handler := func(context.Context, any) (any, error) {
		calls++
		return &pb.VerifyResponse{}, nil
	}
	_, _ = interceptor(withKey("k1"), &pb.VerifyRequest{}, info, handler)
	_, _ = interceptor(withKey("k1"), &pb.VerifyRequest{}, info, handler)
	if calls != 2 {
		t.Errorf("handler ran %d times, want 2 with no cache configured", calls)
	}
}
