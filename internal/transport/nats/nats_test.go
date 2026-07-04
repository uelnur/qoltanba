package nats

import (
	"testing"

	"github.com/nats-io/nats.go"
)

func TestCorrIDFromHeader(t *testing.T) {
	if got := corrIDFromHeader(&nats.Msg{}); got != "" {
		t.Errorf("no header: got %q, want empty", got)
	}

	m := &nats.Msg{Header: nats.Header{}}
	m.Header.Set(nats.MsgIdHdr, "corr-123")
	if got := corrIDFromHeader(m); got != "corr-123" {
		t.Errorf("header set: got %q, want corr-123", got)
	}
}
