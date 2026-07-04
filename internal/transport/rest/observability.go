package rest

import "net/http"

// StatusInfo is the non-sensitive service status shown at /statusz. It must not
// carry secrets or key paths (secrets hygiene rule).
type StatusInfo struct {
	Service      string `json:"service"`
	Version      string `json:"version"`
	LibVersion   string `json:"libVersion"`
	VerifyOnly   bool   `json:"verifyOnly"`
	PoolSize     int    `json:"poolSize"`
	Capabilities any    `json:"capabilities"`
	// SelfTest reports whether the mandatory smoke self-test passed at startup.
	SelfTest bool `json:"selfTest"`
	// Compat is the compatibility verdict for the loaded library
	// (compatible|degraded|incompatible).
	Compat string `json:"compat"`
	// TrustRefresh reports the background trust-anchor refresh state (nil when the
	// caller does not supply it). Kept as any to avoid a transport→infra import.
	TrustRefresh any `json:"trustRefresh,omitempty"`
}

// Observability returns the health/status handler. ready reports whether the
// library is loaded and self-tested (readiness gate); status supplies the
// /statusz payload.
func Observability(ready func() bool, status func() StatusInfo) http.Handler {
	mux := http.NewServeMux()
	// Liveness: the process is up. Always 200 once serving.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	// Readiness: traffic is accepted only after the library self-test passes.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ready == nil || !ready() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	// Info: version, capabilities, mode. No secrets.
	mux.HandleFunc("GET /statusz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, status())
	})
	return mux
}
