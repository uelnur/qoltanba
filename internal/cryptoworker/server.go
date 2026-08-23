package cryptoworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/uelnur/qoltanba/internal/provider"
)

// Driver is what a child process hosts: the port plus the startup self-test the
// parent needs for its compatibility report. *native.Pool satisfies it.
type Driver interface {
	provider.Provider
	SelfTest(ctx context.Context) (provider.SelfTestResult, error)
}

// Serve is the child side: it answers requests read from r on w until r reaches
// EOF (the parent closed the pipe) or a frame cannot be read. Requests are
// handled one at a time, matching the single library instance a child hosts.
//
// A panic in the driver becomes an error response instead of taking the child
// down: the parent survives either way, but an answered call keeps the caller's
// request alive.
func Serve(ctx context.Context, r io.Reader, w io.Writer, d Driver) error {
	for {
		var req request
		switch err := readFrame(r, &req); {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return err
		}
		resp := handle(ctx, d, req)
		if err := writeFrame(w, resp); err != nil {
			return err
		}
	}
}

func handle(ctx context.Context, d Driver, req request) (resp response) {
	defer func() {
		if r := recover(); r != nil {
			resp = response{Err: &wireError{Message: fmt.Sprintf("cryptoworker: panic in driver: %v", r)}}
		}
	}()

	switch req.Op {
	case opCapabilities:
		return reply(d.Capabilities(), nil)
	case opSelfTest:
		return reply(d.SelfTest(ctx))
	case opSignCMS:
		return dispatch(req, func(in provider.SignRequest) (provider.SignResult, error) {
			return d.SignCMS(ctx, in)
		})
	case opVerifyCMS:
		return dispatch(req, func(in provider.VerifyRequest) (provider.VerifyResult, error) {
			return d.VerifyCMS(ctx, in)
		})
	case opSignXML:
		return dispatch(req, func(in provider.SignXMLRequest) (provider.SignResult, error) {
			return d.SignXML(ctx, in)
		})
	case opVerifyXML:
		return dispatch(req, func(in provider.VerifyRequest) (provider.VerifyResult, error) {
			return d.VerifyXML(ctx, in)
		})
	case opSignWSSE:
		return dispatch(req, func(in provider.SignWSSERequest) (provider.SignResult, error) {
			return d.SignWSSE(ctx, in)
		})
	case opExportCert:
		return dispatch(req, func(in exportRequest) (provider.ExportResult, error) {
			return d.ExportOwnerCert(ctx, in.Key, in.Format)
		})
	case opCertProps:
		return dispatch(req, func(in certPropsRequest) (provider.CertProperties, error) {
			return d.CertProperties(ctx, in.Cert, in.Format)
		})
	case opValidateCert:
		return dispatch(req, func(in provider.ValidateRequest) (provider.ValidateResult, error) {
			return d.ValidateCert(ctx, in)
		})
	case opHash:
		return dispatch(req, func(in provider.HashRequest) (provider.HashResult, error) {
			return d.Hash(ctx, in)
		})
	case opSignHash:
		return dispatch(req, func(in provider.SignHashRequest) (provider.SignResult, error) {
			return d.SignHash(ctx, in)
		})
	default:
		return response{Err: &wireError{Message: fmt.Sprintf("cryptoworker: unknown operation %q", req.Op)}}
	}
}

// dispatch decodes the payload for one operation, runs it and encodes the
// outcome. Result and error both travel: the driver fills a partial result on
// failure and the domain reads it.
func dispatch[In, Out any](req request, run func(In) (Out, error)) response {
	var in In
	if err := json.Unmarshal(req.Payload, &in); err != nil {
		return response{Err: &wireError{Message: fmt.Sprintf("cryptoworker: decode %s: %v", req.Op, err)}}
	}
	return reply(run(in))
}

func reply[Out any](out Out, err error) response {
	resp := response{Err: encodeError(err)}
	if payload, merr := json.Marshal(out); merr == nil {
		resp.Payload = payload
	} else if resp.Err == nil {
		resp.Err = &wireError{Message: fmt.Sprintf("cryptoworker: encode result: %v", merr)}
	}
	if res, ok := any(out).(provider.ValidateResult); ok && res.Status == provider.StatusRevoked {
		resp.Revoked = true
	}
	return resp
}

// exportRequest and certPropsRequest carry the two operations whose port
// signature takes loose arguments rather than a request struct.
type exportRequest struct {
	Key    provider.KeyRef     `json:"key"`
	Format provider.CertFormat `json:"format"`
}

type certPropsRequest struct {
	Cert   []byte              `json:"cert"`
	Format provider.CertFormat `json:"format"`
}
