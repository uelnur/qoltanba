package cryptoworker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
	"github.com/uelnur/qoltanba/internal/provider/fake"
)

// stubDriver is the driver a child hosts in tests: the fake provider plus the
// self-test the port does not declare, with hooks for the operations under test.
type stubDriver struct {
	*fake.Provider
	validate func(provider.ValidateRequest) (provider.ValidateResult, error)
	sign     func(provider.SignRequest) (provider.SignResult, error)
	selfTest provider.SelfTestResult
}

func (s stubDriver) ValidateCert(_ context.Context, req provider.ValidateRequest) (provider.ValidateResult, error) {
	if s.validate == nil {
		return provider.ValidateResult{}, nil
	}
	return s.validate(req)
}

func (s stubDriver) SignCMS(_ context.Context, req provider.SignRequest) (provider.SignResult, error) {
	if s.sign == nil {
		return provider.SignResult{}, nil
	}
	return s.sign(req)
}

func (s stubDriver) SelfTest(context.Context) (provider.SelfTestResult, error) {
	return s.selfTest, nil
}

// serveInMemory runs Serve over two pipes and returns a function that performs
// one request/response exchange.
func serveInMemory(t *testing.T, d Driver) func(string, any) response {
	t.Helper()
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), reqR, respW, d) }()
	t.Cleanup(func() {
		reqW.Close()
		if err := <-done; err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("Serve: %v", err)
		}
		respR.Close()
	})
	return func(op string, payload any) response {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		if err := writeFrame(reqW, request{Op: op, Payload: raw}); err != nil {
			t.Fatalf("write request: %v", err)
		}
		var resp response
		if err := readFrame(respR, &resp); err != nil {
			t.Fatalf("read response: %v", err)
		}
		return resp
	}
}

func TestServeDispatchesOperations(t *testing.T) {
	d := stubDriver{
		Provider: &fake.Provider{
			Caps:         provider.Capabilities{Version: "2.0.13", SignCMS: true},
			VerifyResult: provider.VerifyResult{Valid: true, Info: "ok"},
			Props:        fake.Fields(map[string]string{"SUBJECT_COMMONNAME": "CN"}),
		},
		sign: func(req provider.SignRequest) (provider.SignResult, error) {
			if string(req.Data) != "data" || req.Key.Password != "pw" {
				t.Errorf("sign request lost fields: %+v", req)
			}
			return provider.SignResult{Signature: []byte("sig")}, nil
		},
		selfTest: provider.SelfTestResult{Ran: true, OK: true, Algorithm: "SHA256"},
	}
	exchange := serveInMemory(t, d)

	for _, tc := range []struct {
		name    string
		op      string
		payload any
		check   func(t *testing.T, resp response)
	}{
		{"capabilities", opCapabilities, struct{}{}, func(t *testing.T, resp response) {
			var caps provider.Capabilities
			decodePayload(t, resp, &caps)
			if caps.Version != "2.0.13" || !caps.SignCMS {
				t.Errorf("caps = %+v", caps)
			}
		}},
		{"selftest", opSelfTest, struct{}{}, func(t *testing.T, resp response) {
			var res provider.SelfTestResult
			decodePayload(t, resp, &res)
			if !res.OK || !res.Ran {
				t.Errorf("selftest = %+v", res)
			}
		}},
		{"sign", opSignCMS, provider.SignRequest{
			Data: []byte("data"), Key: provider.KeyRef{Password: "pw"},
		}, func(t *testing.T, resp response) {
			var res provider.SignResult
			decodePayload(t, resp, &res)
			if string(res.Signature) != "sig" {
				t.Errorf("signature = %q", res.Signature)
			}
		}},
		{"verify", opVerifyCMS, provider.VerifyRequest{Signature: []byte("sig")}, func(t *testing.T, resp response) {
			var res provider.VerifyResult
			decodePayload(t, resp, &res)
			if !res.Valid || res.Info != "ok" {
				t.Errorf("verify = %+v", res)
			}
		}},
		{"certProperties", opCertProps, certPropsRequest{Cert: []byte("c"), Format: provider.CertPEM},
			func(t *testing.T, resp response) {
				var props provider.CertProperties
				decodePayload(t, resp, &props)
				if v, ok := props.Get("SUBJECT_COMMONNAME"); !ok || v != "CN" {
					t.Errorf("props = %+v", props)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := exchange(tc.op, tc.payload)
			if resp.Err != nil {
				t.Fatalf("error response: %+v", resp.Err)
			}
			tc.check(t, resp)
		})
	}
}

// TestServeFlagsRevokedVerdict pins the signal the parent recycles on without
// decoding payloads.
func TestServeFlagsRevokedVerdict(t *testing.T) {
	d := stubDriver{Provider: &fake.Provider{}, validate: func(provider.ValidateRequest) (provider.ValidateResult, error) {
		return provider.ValidateResult{Status: provider.StatusRevoked}, nil
	}}
	resp := serveInMemory(t, d)(opValidateCert, provider.ValidateRequest{})
	if !resp.Revoked {
		t.Error("revoked verdict not flagged on the wire")
	}
}

// TestServeCarriesResultWithError pins the contract the domain relies on: the
// driver's partial result travels even when the call also returns an error.
func TestServeCarriesResultWithError(t *testing.T) {
	d := stubDriver{Provider: &fake.Provider{}, validate: func(provider.ValidateRequest) (provider.ValidateResult, error) {
		return provider.ValidateResult{Status: provider.StatusRevoked, RawCode: 0x08F0001C},
			provider.NewNativeError("ValidateCert", 0x08F0001C, "revoked", provider.ErrChainInvalid)
	}}
	resp := serveInMemory(t, d)(opValidateCert, provider.ValidateRequest{})

	var res provider.ValidateResult
	decodePayload(t, resp, &res)
	if res.Status != provider.StatusRevoked || res.RawCode != 0x08F0001C {
		t.Errorf("result lost alongside the error: %+v", res)
	}
	if err := resp.Err.decode(); !errors.Is(err, provider.ErrChainInvalid) {
		t.Errorf("error = %v, want ErrChainInvalid", err)
	}
}

func TestServeSurvivesDriverPanic(t *testing.T) {
	d := stubDriver{Provider: &fake.Provider{}, sign: func(provider.SignRequest) (provider.SignResult, error) {
		panic("boom")
	}}
	resp := serveInMemory(t, d)(opSignCMS, provider.SignRequest{})
	if resp.Err == nil {
		t.Fatal("panic should surface as an error response")
	}
}

func TestServeRejectsUnknownOperation(t *testing.T) {
	resp := serveInMemory(t, stubDriver{Provider: &fake.Provider{}})("sign.pdf", struct{}{})
	if resp.Err == nil {
		t.Fatal("unknown operation should be refused")
	}
}

func decodePayload(t *testing.T, resp response, into any) {
	t.Helper()
	if len(resp.Payload) == 0 {
		t.Fatal("empty payload")
	}
	if err := json.Unmarshal(resp.Payload, into); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
}
