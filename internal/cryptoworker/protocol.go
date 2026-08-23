// Package cryptoworker runs the Kalkan driver in child processes.
//
// The library has two defects that no in-process measure can undo. It corrupts
// its process-global crypto/XML state while parsing a revoked OCSP verdict, so a
// later native call aborts with a double free; and it leaks native memory on
// every operation — around 1 MB per CMS verification — with no C-API function to
// release it. Closing a pool instance deliberately does not finalize the library,
// and a SIGABRT is not recoverable, so the only reset boundary is the process
// itself.
//
// Therefore the service keeps no library of its own: every crypto call travels to
// a child process over a length-prefixed JSON pipe, and the parent retires a child
// when it has done enough work, grown too large or seen a revoked verdict — the
// operating system reclaims the leaked memory and the corrupted state along with
// its address space. A child that dies mid-call costs a retry rather than the
// service.
//
// The wire carries key passwords and inline containers, so it must stay a private
// parent↔child pipe (no socket, no logging of payloads). Large inputs are passed
// by path, not by value: the driver reads them with KC_IN_FILE.
package cryptoworker

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/uelnur/qoltanba/internal/provider"
)

// Operations on the wire. They are explicit strings so a mismatched parent and
// child fail loudly instead of misreading a frame.
const (
	opCapabilities = "capabilities"
	opSelfTest     = "selftest"
	opSignCMS      = "sign.cms"
	opVerifyCMS    = "verify.cms"
	opSignXML      = "sign.xml"
	opVerifyXML    = "verify.xml"
	opSignWSSE     = "sign.wsse"
	opExportCert   = "cert.export"
	opCertProps    = "cert.properties"
	opValidateCert = "cert.validate"
	opHash         = "hash"
	opSignHash     = "sign.hash"
)

// maxFrame caps a single frame. Signatures and certificates are kilobytes;
// bulk content goes by path (KC_IN_FILE), so a larger frame means a
// desynchronized stream, which must not turn into an unbounded allocation.
const maxFrame = 64 << 20

// request carries one operation and its provider-level payload. The payload is
// the provider request struct encoded as-is: both ends are the same binary, so
// there is no second contract to keep in sync.
type request struct {
	Op      string          `json:"op"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// response carries the provider-level result, its error, or both: the driver
// fills a result even when it errors (a revocation verdict is an outcome, not a
// fault) and the domain reads both.
type response struct {
	Payload json.RawMessage `json:"payload,omitempty"`
	Err     *wireError      `json:"error,omitempty"`
	// Revoked marks a revocation verdict so the parent can retire the child that
	// saw one without decoding the payload — that verdict is the known trigger of
	// the library's memory corruption.
	Revoked bool `json:"revoked,omitempty"`
}

// wireError carries a provider error across the process boundary with enough
// detail to rebuild it: Key restores the typed sentinel (so errors.Is still
// matches), Code/Detail restore the native error around it.
type wireError struct {
	Op      string `json:"op,omitempty"`
	Code    uint32 `json:"code,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Key     string `json:"key,omitempty"`
	Message string `json:"message"`
}

func encodeError(err error) *wireError {
	if err == nil {
		return nil
	}
	exp := provider.Explain(err)
	we := &wireError{Key: exp.Key, Message: err.Error()}
	var ne *provider.NativeError
	if errors.As(err, &ne) {
		we.Op, we.Code, we.Detail = ne.Op, ne.Code, ne.Detail
	}
	return we
}

func (w *wireError) decode() error {
	if w == nil {
		return nil
	}
	sentinel := provider.SentinelForKey(w.Key)
	// A NativeError keeps the raw code visible to the domain; without one, the
	// sentinel alone is the most faithful reconstruction available.
	if w.Code != 0 || w.Op != "" {
		return provider.NewNativeError(w.Op, w.Code, w.Detail, sentinel)
	}
	if sentinel != nil {
		return sentinel
	}
	return errors.New(w.Message)
}

// writeFrame writes v as a length-prefixed JSON frame.
func writeFrame(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("cryptoworker: encode frame: %w", err)
	}
	if len(payload) > maxFrame {
		return fmt.Errorf("cryptoworker: frame too large (%d bytes)", len(payload))
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(payload)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

// readFrame reads one length-prefixed JSON frame into v. It returns io.EOF when
// the peer closed, which the caller distinguishes from a decode failure.
func readFrame(r io.Reader, v any) error {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return io.EOF
		}
		return err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n > maxFrame {
		return fmt.Errorf("cryptoworker: frame too large (%d bytes)", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return fmt.Errorf("cryptoworker: short frame: %w", err)
	}
	return json.Unmarshal(payload, v)
}
