package cryptoworker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
)

// TestFrameRoundTrip covers the wire for a payload-carrying operation: the
// provider struct is the contract, so it must survive encode/decode intact.
func TestFrameRoundTrip(t *testing.T) {
	in := provider.SignRequest{
		Key:           provider.KeyRef{Storage: provider.StoragePKCS12, Path: "/k.p12", Password: "secret"},
		Data:          []byte("payload"),
		OutPEM:        true,
		CheckCertTime: true,
		TrustedCerts:  []provider.TrustedCert{{Cert: []byte("ca"), Intermediate: true}},
	}
	payload, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var buf bytes.Buffer
	if err := writeFrame(&buf, request{Op: opSignCMS, Payload: payload}); err != nil {
		t.Fatalf("write: %v", err)
	}
	var got request
	if err := readFrame(&buf, &got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Op != opSignCMS {
		t.Fatalf("op = %q", got.Op)
	}
	var out provider.SignRequest
	if err := json.Unmarshal(got.Payload, &out); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if out.Key.Password != in.Key.Password || !bytes.Equal(out.Data, in.Data) || !out.OutPEM {
		t.Errorf("request differs: %+v", out)
	}
	if len(out.TrustedCerts) != 1 || !out.TrustedCerts[0].Intermediate {
		t.Errorf("trusted certs differ: %+v", out.TrustedCerts)
	}
}

// TestErrorRoundTripKeepsSentinel guards the property the domain depends on: a
// provider error keeps matching errors.Is after crossing the process boundary, so
// a verification outcome is still classified as an outcome and not as an
// infrastructure fault.
func TestErrorRoundTripKeepsSentinel(t *testing.T) {
	orig := provider.NewNativeError("VerifyCMS", 0x08F0000B, "cert expired", provider.ErrCertExpired)
	got := encodeError(orig).decode()

	if !errors.Is(got, provider.ErrCertExpired) {
		t.Fatalf("sentinel lost: %v", got)
	}
	var ne *provider.NativeError
	if !errors.As(got, &ne) {
		t.Fatalf("NativeError lost: %v", got)
	}
	if ne.Code != 0x08F0000B || ne.Op != "VerifyCMS" || ne.Detail != "cert expired" {
		t.Errorf("native detail differs: %+v", ne)
	}
}

func TestErrorRoundTripPlainError(t *testing.T) {
	got := encodeError(errors.New("something broke")).decode()
	if got == nil || got.Error() != "something broke" {
		t.Fatalf("plain error lost: %v", got)
	}
	if encodeError(nil) != nil {
		t.Error("nil error should encode to nil")
	}
	var nilWire *wireError
	if nilWire.decode() != nil {
		t.Error("nil wireError should decode to nil")
	}
}

func TestReadFrameEmptyStreamIsEOF(t *testing.T) {
	var v request
	if err := readFrame(bytes.NewReader(nil), &v); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
	// A truncated header means the peer died mid-frame; it must not be mistaken
	// for a clean close, but it must not hang either.
	if err := readFrame(bytes.NewReader([]byte{0, 0}), &v); !errors.Is(err, io.EOF) {
		t.Fatalf("truncated header err = %v, want io.EOF", err)
	}
}

func TestReadFrameRejectsOversizedFrame(t *testing.T) {
	head := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	var v request
	err := readFrame(bytes.NewReader(head), &v)
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want a size error", err)
	}
}
