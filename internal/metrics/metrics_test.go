package metrics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
)

func scrape(t *testing.T, r *Recorder) string {
	t.Helper()
	rw := httptest.NewRecorder()
	r.Handler().ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(rw.Result().Body)
	return string(body)
}

func TestObserve_CountsAndTimes(t *testing.T) {
	r := New()
	r.Observe("rest", "sign", "ok", 5*time.Millisecond)
	r.Observe("rest", "sign", "ok", 5*time.Millisecond)
	r.Observe("grpc", "verify", "invalidargument", time.Millisecond)

	out := scrape(t, r)
	if !strings.Contains(out, `qoltanba_requests_total{op="sign",outcome="ok",transport="rest"} 2`) {
		t.Errorf("missing/incorrect rest sign counter:\n%s", out)
	}
	if !strings.Contains(out, `qoltanba_requests_total{op="verify",outcome="invalidargument",transport="grpc"} 1`) {
		t.Errorf("missing grpc verify counter:\n%s", out)
	}
	if !strings.Contains(out, `qoltanba_request_duration_seconds_count{op="sign",transport="rest"} 2`) {
		t.Errorf("missing duration histogram:\n%s", out)
	}
}

func TestNilRecorderIsNoOp(t *testing.T) {
	var r *Recorder                              // nil
	r.Observe("rest", "sign", "ok", time.Second) // must not panic
	r.BindPool(func() (int, int) { return 1, 2 })
	r.BindTrust(func() int { return 3 })
	r.BindCRL(func() (uint64, uint64) { return 4, 5 })
	if r.Handler() == nil {
		t.Error("nil Recorder should still return a non-nil Handler")
	}
}

func TestBindPoolAndCRL(t *testing.T) {
	r := New()
	r.BindPool(func() (int, int) { return 3, 8 }) // 3 busy of 8 → 5 idle
	r.BindTrust(func() int { return 42 })
	r.BindCRL(func() (uint64, uint64) { return 7, 2 })

	out := scrape(t, r)
	for _, want := range []string{
		`qoltanba_pool_workers{state="busy"} 3`,
		`qoltanba_pool_workers{state="idle"} 5`,
		`qoltanba_trust_anchors 42`,
		`qoltanba_crl_cache_total{result="hit"} 7`,
		`qoltanba_crl_cache_total{result="miss"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scrape missing %q:\n%s", want, out)
		}
	}
}

func TestInstrumentHTTP_RecordsPatternAndStatus(t *testing.T) {
	r := New()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /cert/info", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	h := r.InstrumentHTTP("rest", mux)

	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/cert/info", nil))

	out := scrape(t, r)
	if !strings.Contains(out, `qoltanba_requests_total{op="cert.info",outcome="client_error",transport="rest"} 1`) {
		t.Errorf("HTTP instrumentation wrong:\n%s", out)
	}
}

func TestUnaryInterceptor_RecordsMethodAndOutcome(t *testing.T) {
	r := New()
	ic := r.UnaryInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/qoltanba.v1.SignatureService/CertValidate"}
	_, _ = ic(context.Background(), nil, info, func(context.Context, any) (any, error) { return "ok", nil })

	out := scrape(t, r)
	if !strings.Contains(out, `qoltanba_requests_total{op="certvalidate",outcome="ok",transport="grpc"} 1`) {
		t.Errorf("gRPC interceptor wrong:\n%s", out)
	}
}

func TestOpFromPattern(t *testing.T) {
	cases := map[string]string{
		"POST /sign":          "sign",
		"POST /sign/add":      "sign.add",
		"POST /cert/validate": "cert.validate",
		"":                    "unknown",
	}
	for in, want := range cases {
		if got := opFromPattern(in); got != want {
			t.Errorf("opFromPattern(%q) = %q, want %q", in, got, want)
		}
	}
}
