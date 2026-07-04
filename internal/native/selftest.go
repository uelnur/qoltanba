package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/uelnur/qoltanba/internal/provider"
)

// selfTestVector is a fixed input hashed during the smoke self-test. Its content
// is irrelevant: correctness is judged by comparing the library's digest to Go's
// own SHA-256 of the same bytes, not to a stored constant.
var selfTestVector = []byte("qoltanba self-test vector v1")

// SelfTest runs the mandatory smoke check: it hashes a fixed vector with the
// library (SHA-256) and compares the result to Go's crypto/sha256 of the same
// input. A match proves the library not only loaded but computes correctly. It
// returns a structured result; the error is reserved for infrastructure
// failures (pool closed), not for a logical mismatch — a mismatch is reported
// via SelfTestResult.OK=false so callers can attach it to a compatibility
// report. If the library lacks HashData, the test is marked not run (Ran=false),
// which the compatibility layer treats as "correctness unproven", not "broken".
func (p *Pool) SelfTest(ctx context.Context) (provider.SelfTestResult, error) {
	res := provider.SelfTestResult{Algorithm: "SHA256"}
	err := p.submit(ctx, func(inst kalkanInstance) error {
		if !inst.has(capHashData) {
			res.Detail = "HashData is not available in this library version; correctness could not be proven"
			return nil
		}
		res.Ran = true
		out, herr := inst.hashData("SHA256", kcHashSHA256, selfTestVector)
		if herr != nil {
			res.Detail = "HashData call failed: " + herr.Error()
			return nil //nolint:nilerr // outcome is carried in res (OK=false); a hash failure is not a submit error
		}
		want := sha256.Sum256(selfTestVector)
		if digestMatches(out, want[:]) {
			res.OK = true
			res.Detail = "HashData/SHA256 matches the reference digest"
		} else {
			res.Detail = fmt.Sprintf("HashData/SHA256 mismatch: library returned %d bytes that do not match the expected SHA-256", len(out))
		}
		return nil
	})
	return res, err
}

// digestMatches reports whether got equals the reference digest, tolerating the
// output encoding the library may apply: raw bytes, or the digest rendered as
// hex or base64 text. This keeps the self-test robust across library builds
// without assuming one output form.
func digestMatches(got, want []byte) bool {
	if bytes.Equal(got, want) {
		return true
	}
	// Tolerate NUL padding on a raw digest returned in an oversized buffer.
	trimmed := bytes.TrimRight(got, "\x00")
	if bytes.Equal(trimmed, want) {
		return true
	}
	s := strings.TrimSpace(string(trimmed))
	if dec, err := hex.DecodeString(s); err == nil && bytes.Equal(dec, want) {
		return true
	}
	if dec, err := base64.StdEncoding.DecodeString(s); err == nil && bytes.Equal(dec, want) {
		return true
	}
	return false
}
