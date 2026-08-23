package grpc

import (
	"context"
	"encoding/json"
	"fmt"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/uelnur/qoltanba/internal/idempotency"
)

// Idempotency for gRPC rides on request metadata rather than a field in the
// contract: the key is about delivery, not about the operation, and an
// at-least-once redelivery repeats the same message. That keeps the proto free of
// a transport concern and matches how the REST side uses a header.
//
// Only unary calls are covered. A streamed batch is deliberately excluded, as on
// the REST side: replaying a stream means buffering it whole, which is exactly
// what streaming exists to avoid.

// idempotencyKey is the metadata key a client sets to make a call replayable.
const idempotencyKey = "idempotency-key"

// cachedReply is what a replayable call stores: the response plus the name of its
// message type, so a replay rebuilds it from the registry instead of re-running
// the handler — re-running would defeat the point.
type cachedReply struct {
	Type string          `json:"type"`
	Body json.RawMessage `json:"body"`
}

// IdempotencyInterceptor replays the first response for a repeated key instead of
// re-executing the call. With a nil cache it is a pass-through, so wiring it
// unconditionally is safe.
func IdempotencyInterceptor(cache *idempotency.Cache) grpclib.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpclib.UnaryServerInfo, handler grpclib.UnaryHandler) (any, error) {
		key := metadataValue(ctx, idempotencyKey)
		if cache == nil || key == "" {
			return handler(ctx, req)
		}

		var fresh any
		blob, replayed, err := cache.Do(ctx, info.FullMethod+"\x00"+key, func() ([]byte, error) {
			out, herr := handler(ctx, req)
			if herr != nil {
				return nil, herr // never cache a failure: a retry must get a real attempt
			}
			fresh = out
			return encodeReply(out)
		})
		if err != nil {
			return nil, err
		}
		if !replayed {
			return fresh, nil
		}
		out, derr := decodeReply(blob)
		if derr != nil {
			// A cache entry we cannot rebuild is useless but not fatal: running the
			// call again is correct for every operation here (they compute over their
			// inputs and mutate nothing).
			return handler(ctx, req)
		}
		return out, nil
	}
}

func encodeReply(out any) ([]byte, error) {
	msg, ok := out.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("response is not a proto message")
	}
	body, err := protojson.Marshal(msg)
	if err != nil {
		return nil, err
	}
	return json.Marshal(cachedReply{
		Type: string(msg.ProtoReflect().Descriptor().FullName()),
		Body: body,
	})
}

func decodeReply(blob []byte) (proto.Message, error) {
	var cached cachedReply
	if err := json.Unmarshal(blob, &cached); err != nil {
		return nil, err
	}
	mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(cached.Type))
	if err != nil {
		return nil, err
	}
	msg := mt.New().Interface()
	if err := protojson.Unmarshal(cached.Body, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func metadataValue(ctx context.Context, key string) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if vals := md.Get(key); len(vals) > 0 {
		return vals[0]
	}
	return ""
}
