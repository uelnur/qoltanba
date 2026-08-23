// Package metrics is the Prometheus instrumentation layer. It owns a private
// registry and the service's metric vocabulary, and exposes helpers the
// transports call at their boundary (HTTP middleware, gRPC interceptor, MQ hook)
// so every operation is counted and timed by {transport, op, outcome}. Internal
// gauges (pool utilization, trust anchors, CRL cache) are bound to live sources
// via BindPool/BindTrust/BindCRL and read at scrape time.
//
// A nil *Recorder is a valid no-op: when metrics are not wired, every method is a
// cheap return, so call sites need no guard.
package metrics

import (
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Recorder holds the registry and the request metrics.
type Recorder struct {
	reg      *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// New builds a Recorder with a fresh registry, the request metrics and the
// standard Go/process collectors.
func New() *Recorder {
	reg := prometheus.NewRegistry()
	r := &Recorder{
		reg: reg,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "qoltanba_requests_total",
			Help: "Operations handled, by transport, op and outcome.",
		}, []string{"transport", "op", "outcome"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "qoltanba_request_duration_seconds",
			Help:    "Operation latency in seconds, by transport and op.",
			Buckets: prometheus.DefBuckets,
		}, []string{"transport", "op"}),
	}
	reg.MustRegister(
		r.requests, r.duration,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return r
}

// Observe records one completed operation. Safe on a nil Recorder.
func (r *Recorder) Observe(transport, op, outcome string, d time.Duration) {
	if r == nil {
		return
	}
	r.requests.WithLabelValues(transport, op, outcome).Inc()
	r.duration.WithLabelValues(transport, op).Observe(d.Seconds())
}

// Handler returns the /metrics scrape handler (404 on a nil Recorder).
func (r *Recorder) Handler() http.Handler {
	if r == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// BindPool registers a gauge reading pool utilization at scrape time. stats
// returns (inUse, size). No-op on a nil Recorder or nil stats.
func (r *Recorder) BindPool(stats func() (inUse, size int)) {
	if r == nil || stats == nil {
		return
	}
	r.reg.MustRegister(poolCollector{stats: stats, desc: prometheus.NewDesc(
		"qoltanba_pool_workers", "Kalkan worker pool utilization by state.", []string{"state"}, nil)})
}

// BindTrust registers a gauge for the current trust-anchor count. count is read
// at scrape time. No-op on a nil Recorder or nil count.
func (r *Recorder) BindTrust(count func() int) {
	if r == nil || count == nil {
		return
	}
	r.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "qoltanba_trust_anchors",
		Help: "Trusted CA anchors currently loaded.",
	}, func() float64 { return float64(count()) }))
}

// BindCRL registers cumulative CRL cache hit/miss counters. stats returns
// (hits, misses). No-op on a nil Recorder or nil stats.
func (r *Recorder) BindCRL(stats func() (hits, misses uint64)) {
	if r == nil || stats == nil {
		return
	}
	r.reg.MustRegister(crlCollector{stats: stats, desc: prometheus.NewDesc(
		"qoltanba_crl_cache_total", "CRL cache lookups by result.", []string{"result"}, nil)})
}

// BindOCSPCache registers cumulative OCSP answer-cache hit/miss counters. Every
// hit is a request the responder did not receive. No-op on a nil Recorder or nil
// stats.
func (r *Recorder) BindOCSPCache(stats func() (hits, misses uint64)) {
	if r == nil || stats == nil {
		return
	}
	r.reg.MustRegister(crlCollector{stats: stats, desc: prometheus.NewDesc(
		"qoltanba_ocsp_cache_total", "OCSP answer cache lookups by result.", []string{"result"}, nil)})
}

// BindOIDC registers a gauge for the current stored-challenge count. count is
// read at scrape time. No-op on a nil Recorder or nil count.
func (r *Recorder) BindOIDC(count func() int) {
	if r == nil || count == nil {
		return
	}
	r.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "qoltanba_oidc_challenges",
		Help: "OIDC login challenges currently outstanding.",
	}, func() float64 { return float64(count()) }))
}

// BindCertWatch registers per-certificate expiry and revocation gauges. states
// is read at scrape time. The label set is the watch list, which an operator
// curates — it is bounded by design, unlike labeling every certificate the
// service ever sees. No-op on a nil Recorder or nil states.
func (r *Recorder) BindCertWatch(states func() []CertWatchState) {
	if r == nil || states == nil {
		return
	}
	r.reg.MustRegister(certWatchCollector{
		states: states,
		expiry: prometheus.NewDesc("qoltanba_watched_cert_expiry_seconds",
			"Seconds until a watched certificate expires (negative once expired).",
			[]string{"file", "subject"}, nil),
		revoked: prometheus.NewDesc("qoltanba_watched_cert_revoked",
			"1 when a watched certificate is revoked, 0 otherwise.",
			[]string{"file", "subject"}, nil),
		healthy: prometheus.NewDesc("qoltanba_watched_cert_check_ok",
			"1 when the last check of a watched certificate completed, 0 when it could not.",
			[]string{"file", "subject"}, nil),
	})
}

// CertWatchState is the metrics-facing view of one watched certificate, declared
// here so the collector does not pull the watcher package into this one.
type CertWatchState struct {
	File      string
	Subject   string
	ExpiresIn time.Duration
	HasExpiry bool
	Revoked   bool
	Failed    bool
}

type certWatchCollector struct {
	states                   func() []CertWatchState
	expiry, revoked, healthy *prometheus.Desc
}

func (c certWatchCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.expiry
	ch <- c.revoked
	ch <- c.healthy
}

func (c certWatchCollector) Collect(ch chan<- prometheus.Metric) {
	for _, s := range c.states() {
		if s.HasExpiry {
			ch <- prometheus.MustNewConstMetric(c.expiry, prometheus.GaugeValue,
				s.ExpiresIn.Seconds(), s.File, s.Subject)
		}
		ch <- prometheus.MustNewConstMetric(c.revoked, prometheus.GaugeValue,
			boolGauge(s.Revoked), s.File, s.Subject)
		ch <- prometheus.MustNewConstMetric(c.healthy, prometheus.GaugeValue,
			boolGauge(!s.Failed), s.File, s.Subject)
	}
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// BindChallenges registers a gauge for outstanding standalone challenges. count
// is read at scrape time. No-op on a nil Recorder or nil count.
func (r *Recorder) BindChallenges(count func() int) {
	if r == nil || count == nil {
		return
	}
	r.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "qoltanba_challenges",
		Help: "Standalone challenge-response challenges currently outstanding.",
	}, func() float64 { return float64(count()) }))
}

// BindMultisign registers a gauge for signing rounds currently open. count is
// read at scrape time. No-op on a nil Recorder or nil count.
func (r *Recorder) BindMultisign(count func() int) {
	if r == nil || count == nil {
		return
	}
	r.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "qoltanba_multisign_sessions",
		Help: "Multi-signature rounds currently open.",
	}, func() float64 { return float64(count()) }))
}

// BindQR registers a gauge for the current stored QR-session count. count is read
// at scrape time. No-op on a nil Recorder or nil count.
func (r *Recorder) BindQR(count func() int) {
	if r == nil || count == nil {
		return
	}
	r.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "qoltanba_qr_sessions",
		Help: "eGov Mobile QR sessions currently outstanding.",
	}, func() float64 { return float64(count()) }))
}

// BindCryptoWorker registers cumulative counters for the out-of-process driver
// children. stats returns (spawns, crashes, recycles, timeouts). Recycles are
// routine (they contain the library's memory leak); a rising crash count is the
// library defect surfacing in production and is worth alerting on. No-op on a nil
// Recorder or nil stats.
func (r *Recorder) BindCryptoWorker(stats func() (spawns, crashes, recycles, timeouts, hotSwaps uint64)) {
	if r == nil || stats == nil {
		return
	}
	r.reg.MustRegister(cryptoWorkerCollector{stats: stats, desc: prometheus.NewDesc(
		"qoltanba_crypto_worker_total", "Crypto child-process lifecycle events by kind.", []string{"event"}, nil)})
}

// cryptoWorkerCollector emits child-process lifecycle counters from a live stats
// function.
type cryptoWorkerCollector struct {
	stats func() (spawns, crashes, recycles, timeouts, hotSwaps uint64)
	desc  *prometheus.Desc
}

func (c cryptoWorkerCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c cryptoWorkerCollector) Collect(ch chan<- prometheus.Metric) {
	spawns, crashes, recycles, timeouts, hotSwaps := c.stats()
	for _, m := range []struct {
		event string
		value uint64
	}{{"spawn", spawns}, {"crash", crashes}, {"recycle", recycles}, {"timeout", timeouts}, {"hotswap", hotSwaps}} {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(m.value), m.event)
	}
}

// poolCollector emits busy/idle worker gauges from a live stats function.
type poolCollector struct {
	stats func() (inUse, size int)
	desc  *prometheus.Desc
}

func (c poolCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c poolCollector) Collect(ch chan<- prometheus.Metric) {
	inUse, size := c.stats()
	idle := size - inUse
	if idle < 0 {
		idle = 0
	}
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, float64(inUse), "busy")
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, float64(idle), "idle")
}

// crlCollector emits hit/miss counters from a live stats function.
type crlCollector struct {
	stats func() (hits, misses uint64)
	desc  *prometheus.Desc
}

func (c crlCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c crlCollector) Collect(ch chan<- prometheus.Metric) {
	hits, misses := c.stats()
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(hits), "hit")
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(misses), "miss")
}

// opFromPattern derives an op label from a routed HTTP pattern ("POST /cert/info"
// → "cert.info"). Empty (unmatched) yields "unknown".
func opFromPattern(pattern string) string {
	if pattern == "" {
		return "unknown"
	}
	if i := strings.IndexByte(pattern, '/'); i >= 0 {
		pattern = pattern[i:]
	}
	return strings.ReplaceAll(strings.Trim(pattern, "/"), "/", ".")
}
