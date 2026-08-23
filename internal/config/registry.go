package config

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// entry declares one setting once. From key/flag/env the three surfaces are
// derived; kind drives flag registration and env/file parsing. secret marks a
// value that must be redacted in dumps and only sourced from env/*_FILE.
type entry struct {
	key    string // koanf key, e.g. "log.level"
	flag   string // flag name, e.g. "log-level"
	env    string // env suffix, full var is QOLTANBA_<env>, e.g. "LOG_LEVEL"
	usage  string
	kind   kind
	def    any
	secret bool
}

type kind int

const (
	kindString kind = iota
	kindBool
	kindInt
	kindStringSlice
)

// registry is the single source of truth for all settings.
func registry() []entry {
	return []entry{
		{key: "lib.path", flag: "lib-path", env: "LIB_PATH", kind: kindString, def: "", usage: "path to libkalkancryptwr-64.so (BYOL)"},
		{key: "lib.version", flag: "lib-version", env: "LIB_VERSION", kind: kindString, def: "", usage: "override library version detection"},
		{key: "lib.isolated", flag: "lib-isolated", env: "LIB_ISOLATED", kind: kindBool, def: false, usage: "isolate pool instances (dlmopen; Linux)"},
		{key: "lib.isolation-deps", flag: "lib-isolation-deps", env: "LIB_ISOLATION_DEPS", kind: kindStringSlice, def: []string{}, usage: "comma-separated namespace deps for isolation"},
		{key: "lib.min-version", flag: "lib-min-version", env: "LIB_MIN_VERSION", kind: kindString, def: "2.0.0", usage: "minimum supported library version (below it is incompatible)"},
		{key: "lib.compat", flag: "lib-compat", env: "LIB_COMPAT", kind: kindString, def: "strict", usage: "startup compatibility policy: strict|warn|off (self-test failure always blocks)"},
		{key: "workers", flag: "workers", env: "WORKERS", kind: kindInt, def: 1, usage: "number of pool instances (>1 requires lib-isolated)"},
		{key: "verify-only", flag: "verify-only", env: "VERIFY_ONLY", kind: kindBool, def: false, usage: "disable the key path and sign operations"},
		{key: "locale", flag: "locale", env: "LOCALE", kind: kindString, def: "en", usage: "default language for error messages: en|ru|kk (a request may override it)"},
		{key: "console.enabled", flag: "console", env: "CONSOLE_ENABLED", kind: kindBool, def: false, usage: "serve the try-it console at /console"},
		{key: "console.sandbox-key", flag: "console-sandbox-key", env: "CONSOLE_SANDBOX_KEY", kind: kindString, def: "", usage: "demo .p12 for POST /sandbox/sign (test container only — anyone reaching it can sign)"},
		{key: "console.sandbox-key-password", flag: "console-sandbox-key-password", env: "CONSOLE_SANDBOX_KEY_PASSWORD", kind: kindString, def: "", secret: true, usage: "password of the sandbox demo container"},
		{key: "audit.enabled", flag: "audit", env: "AUDIT_ENABLED", kind: kindBool, def: false, usage: "record signing and verification into a hash-chained, signed journal"},
		{key: "audit.path", flag: "audit-path", env: "AUDIT_PATH", kind: kindString, def: "", usage: "journal file (JSON Lines, append-only); required when audit.enabled"},
		{key: "audit.sync", flag: "audit-sync", env: "AUDIT_SYNC", kind: kindBool, def: false, usage: "flush each journal entry to disk before the operation returns"},
		{key: "audit.expose", flag: "audit-expose", env: "AUDIT_EXPOSE", kind: kindBool, def: false, usage: "serve /audit/verify and /audit/export (the journal names digests and signers)"},
		{key: "multisign.enabled", flag: "multisign", env: "MULTISIGN_ENABLED", kind: kindBool, def: false, usage: "enable multi-signature session endpoints (/multisign/sessions)"},
		{key: "multisign.ttl", flag: "multisign-ttl", env: "MULTISIGN_TTL", kind: kindString, def: "168h", usage: "how long a signing round waits before expiring, as a Go duration (168h = 7d)"},
		{key: "multisign.store", flag: "multisign-store", env: "MULTISIGN_STORE", kind: kindString, def: "memory", usage: "session store: memory (ephemeral) | bolt (survives restart)"},
		{key: "multisign.bolt-path", flag: "multisign-bolt-path", env: "MULTISIGN_BOLT_PATH", kind: kindString, def: "", usage: "bbolt database path (required when multisign.store=bolt)"},
		{key: "portal.enabled", flag: "portal", env: "PORTAL_ENABLED", kind: kindBool, def: false, usage: "serve the human verification page at /verify/portal (accepts uploads from any reachable client)"},
		{key: "certwatch.enabled", flag: "certwatch", env: "CERTWATCH_ENABLED", kind: kindBool, def: false, usage: "watch certificates for revocation and upcoming expiry (metrics + optional webhook)"},
		{key: "certwatch.dir", flag: "certwatch-dir", env: "CERTWATCH_DIR", kind: kindString, def: "", usage: "directory of watched certificates (.pem/.cer/.crt/.der)"},
		{key: "certwatch.interval", flag: "certwatch-interval", env: "CERTWATCH_INTERVAL", kind: kindString, def: "6h", usage: "how often watched certificates are re-checked, as a Go duration"},
		{key: "certwatch.warn-from", flag: "certwatch-warn-from", env: "CERTWATCH_WARN_FROM", kind: kindString, def: "720h", usage: "how far ahead an upcoming expiry is reported, as a Go duration (720h = 30d)"},
		{key: "certwatch.webhook-url", flag: "certwatch-webhook-url", env: "CERTWATCH_WEBHOOK_URL", kind: kindString, def: "", secret: true, usage: "URL notified when a watched certificate is revoked or expiring"},
		{key: "certwatch.check-revocation", flag: "certwatch-check-revocation", env: "CERTWATCH_CHECK_REVOCATION", kind: kindBool, def: true, usage: "check revocation via OCSP on every sweep (off watches expiry only)"},
		{key: "challenge.enabled", flag: "challenge", env: "CHALLENGE_ENABLED", kind: kindBool, def: false, usage: "enable the standalone challenge-response endpoints (POST /challenge, /challenge/confirm)"},
		{key: "challenge.ttl", flag: "challenge-ttl", env: "CHALLENGE_TTL", kind: kindString, def: "5m", usage: "how long an issued challenge stays usable, as a Go duration"},
		{key: "challenge.store", flag: "challenge-store", env: "CHALLENGE_STORE", kind: kindString, def: "memory", usage: "challenge store: memory (ephemeral) | bolt (survives restart)"},
		{key: "challenge.bolt-path", flag: "challenge-bolt-path", env: "CHALLENGE_BOLT_PATH", kind: kindString, def: "", usage: "bbolt database path (required when challenge.store=bolt)"},
		{key: "challenge.require-ocsp", flag: "challenge-require-ocsp", env: "CHALLENGE_REQUIRE_OCSP", kind: kindBool, def: false, usage: "check signer revocation on every confirmation (fails closed when inconclusive)"},
		{key: "receipts.enabled", flag: "receipts", env: "RECEIPTS_ENABLED", kind: kindBool, def: false, usage: "sign verification outcomes with the service key (verify flag \"receipt\"); JWKS at /jwks.json"},
		{key: "receipts.signed-qr", flag: "signed-qr", env: "SIGNED_QR_ENABLED", kind: kindBool, def: false, usage: "issue and verify QR-carried signed documents (/qr/documents)"},
		{key: "receipts.issuer", flag: "receipts-issuer", env: "RECEIPTS_ISSUER", kind: kindString, def: "", usage: "iss claim of signed receipts (empty falls back to oidc.issuer)"},
		{key: "crypto-worker.enabled", flag: "crypto-worker", env: "CRYPTO_WORKER_ENABLED", kind: kindBool, def: true, usage: "run crypto operations in child processes (contains the library's memory leak and revoked-OCSP crash)"},
		{key: "crypto-worker.processes", flag: "crypto-worker-processes", env: "CRYPTO_WORKER_PROCESSES", kind: kindInt, def: 0, usage: "concurrent crypto child processes (0 uses the worker count)"},
		{key: "crypto-worker.timeout", flag: "crypto-worker-timeout", env: "CRYPTO_WORKER_TIMEOUT", kind: kindString, def: "60s", usage: "per-operation timeout, as a Go duration (bounds a hung native call)"},
		{key: "crypto-worker.max-ops", flag: "crypto-worker-max-ops", env: "CRYPTO_WORKER_MAX_OPS", kind: kindInt, def: 1000, usage: "retire a child after this many operations (negative disables)"},
		{key: "crypto-worker.max-rss-mb", flag: "crypto-worker-max-rss-mb", env: "CRYPTO_WORKER_MAX_RSS_MB", kind: kindInt, def: 512, usage: "retire a child once it reaches this resident size in MiB (negative disables)"},
		{key: "crypto-worker.standby", flag: "crypto-worker-standby", env: "CRYPTO_WORKER_STANDBY", kind: kindInt, def: 1, usage: "pre-warmed spare children ready to replace a recycled one (0 starts them on demand)"},
		{key: "crypto-worker.keep-after-revoked", flag: "crypto-worker-keep-after-revoked", env: "CRYPTO_WORKER_KEEP_AFTER_REVOKED", kind: kindBool, def: false, usage: "keep a child that saw a revoked verdict (diagnostics only)"},
		{key: "http.enabled", flag: "http", env: "HTTP_ENABLED", kind: kindBool, def: false, usage: "enable the REST transport"},
		{key: "http.addr", flag: "http-addr", env: "HTTP_ADDR", kind: kindString, def: ":8080", usage: "REST listen address (:port or unix:/path)"},
		{key: "grpc.enabled", flag: "grpc", env: "GRPC_ENABLED", kind: kindBool, def: false, usage: "enable the gRPC transport"},
		{key: "grpc.addr", flag: "grpc-addr", env: "GRPC_ADDR", kind: kindString, def: ":9091", usage: "gRPC listen address (:port or unix:/path)"},
		{key: "amqp.url", flag: "amqp-url", env: "AMQP_URL", kind: kindString, def: "", secret: true, usage: "RabbitMQ URL (amqp://…); setting it enables the transport"},
		{key: "amqp.queue", flag: "amqp-queue", env: "AMQP_QUEUE", kind: kindString, def: "", usage: "RabbitMQ request queue to consume"},
		{key: "amqp.reply-queue", flag: "amqp-reply-queue", env: "AMQP_REPLY_QUEUE", kind: kindString, def: "", usage: "fixed reply queue (empty defers to each message's reply-to)"},
		{key: "amqp.prefetch", flag: "amqp-prefetch", env: "AMQP_PREFETCH", kind: kindInt, def: 0, usage: "RabbitMQ QoS prefetch (0 uses the worker count)"},
		{key: "kafka.brokers", flag: "kafka-brokers", env: "KAFKA_BROKERS", kind: kindStringSlice, def: []string{}, usage: "Kafka seed brokers; setting them enables the transport"},
		{key: "kafka.topic", flag: "kafka-topic", env: "KAFKA_TOPIC", kind: kindString, def: "", usage: "Kafka request topic to consume"},
		{key: "kafka.reply-topic", flag: "kafka-reply-topic", env: "KAFKA_REPLY_TOPIC", kind: kindString, def: "", usage: "default Kafka reply topic (a reply-topic header overrides it)"},
		{key: "kafka.group", flag: "kafka-group", env: "KAFKA_GROUP", kind: kindString, def: "qoltanba", usage: "Kafka consumer group id"},
		{key: "nats.url", flag: "nats-url", env: "NATS_URL", kind: kindString, def: "", secret: true, usage: "NATS URL (nats://…); setting it enables the transport"},
		{key: "nats.subject", flag: "nats-subject", env: "NATS_SUBJECT", kind: kindString, def: "", usage: "NATS request subject to consume"},
		{key: "nats.queue", flag: "nats-queue", env: "NATS_QUEUE", kind: kindString, def: "", usage: "NATS queue group for load balancing (optional)"},
		{key: "nats.reply-subject", flag: "nats-reply-subject", env: "NATS_REPLY_SUBJECT", kind: kindString, def: "", usage: "fallback reply subject (empty defers to each message's reply-to)"},
		{key: "nats.durable", flag: "nats-durable", env: "NATS_DURABLE", kind: kindString, def: "qoltanba", usage: "NATS JetStream durable consumer name"},
		{key: "keys.allow-inline", flag: "keys-allow-inline", env: "KEYS_ALLOW_INLINE", kind: kindBool, def: false, usage: "accept inline PKCS#12 in requests (TLS/local only)"},
		{key: "sign.default-timestamp", flag: "sign-default-timestamp", env: "SIGN_DEFAULT_TIMESTAMP", kind: kindBool, def: false, usage: "add a TSA timestamp by default when a sign request does not specify"},
		{key: "trust.ca-dir", flag: "trust-ca-dir", env: "TRUST_CA_DIR", kind: kindString, def: "", usage: "directory of trusted CA PEM files"},
		{key: "trust.fetch-aia", flag: "trust-fetch-aia", env: "TRUST_FETCH_AIA", kind: kindBool, def: false, usage: "download missing issuers via AIA during chain building"},
		{key: "trust.aia-timeout", flag: "trust-aia-timeout", env: "TRUST_AIA_TIMEOUT", kind: kindInt, def: 5, usage: "AIA fetch per-request timeout (seconds)"},
		{key: "trust.use-rk-registry", flag: "trust-use-rk-registry", env: "TRUST_USE_RK_REGISTRY", kind: kindBool, def: false, usage: "preload trust anchors from the official RK CA registry"},
		{key: "trust.rk-include-test", flag: "trust-rk-include-test", env: "TRUST_RK_INCLUDE_TEST", kind: kindBool, def: false, usage: "include RK test roots when preloading the registry"},
		{key: "trust.verify-chain", flag: "trust-verify-chain", env: "TRUST_VERIFY_CHAIN", kind: kindBool, def: false, usage: "cryptographically validate the signer chain via Kalkan (incl. GOST)"},
		{key: "trust.refresh-interval", flag: "trust-refresh-interval", env: "TRUST_REFRESH_INTERVAL", kind: kindString, def: "", usage: "background anchor-refresh cadence (e.g. 24h); empty=auto (24h with RK registry), 0/off=disabled"},
		{key: "trust.crl-cache", flag: "trust-crl-cache", env: "TRUST_CRL_CACHE", kind: kindBool, def: false, usage: "cache CRLs by distribution point for Method=CRL validation without inline CRL"},
		{key: "trust.crl-spool-dir", flag: "trust-crl-spool-dir", env: "TRUST_CRL_SPOOL_DIR", kind: kindString, def: "", usage: "spool CRL bodies to this directory (persistent, warm-started); empty keeps them in memory"},
		{key: "trust.ocsp-cache", flag: "trust-ocsp-cache", env: "TRUST_OCSP_CACHE", kind: kindBool, def: false, usage: "reuse recent OCSP answers instead of re-asking the responder (also staples the raw response)"},
		{key: "trust.ocsp-cache-ttl", flag: "trust-ocsp-cache-ttl", env: "TRUST_OCSP_CACHE_TTL", kind: kindString, def: "10m", usage: "freshness bound for an OCSP answer without nextUpdate, as a Go duration"},
		{key: "trust.ocsp-cache-max-entries", flag: "trust-ocsp-cache-max-entries", env: "TRUST_OCSP_CACHE_MAX_ENTRIES", kind: kindInt, def: 0, usage: "cap on cached OCSP answers (0 = default 4096)"},
		{key: "trust.crl-cache-max-mb", flag: "trust-crl-cache-max-mb", env: "TRUST_CRL_CACHE_MAX_MB", kind: kindInt, def: 0, usage: "cap on total cached CRL bytes in MiB (0 = default 256)"},
		{key: "trust.tsa-policies", flag: "trust-tsa-policies", env: "TRUST_TSA_POLICIES", kind: kindStringSlice, def: []string{}, usage: "TSA policy OIDs accepted for CAdES-T (e.g. 1.2.398.3.3.2.6.4); empty enforces none"},
		{key: "trust.crl-fail-policy", flag: "trust-crl-fail-policy", env: "TRUST_CRL_FAIL_POLICY", kind: kindString, def: "soft", usage: "CRL fail policy when a managed CRL is unreliable: soft (fall back to OCSP) | hard (fail closed)"},
		{key: "log.level", flag: "log-level", env: "LOG_LEVEL", kind: kindString, def: "info", usage: "log level: debug|info|warn|error"},
		{key: "log.format", flag: "log-format", env: "LOG_FORMAT", kind: kindString, def: "text", usage: "log format: text|json"},
		{key: "metrics.enabled", flag: "metrics", env: "METRICS_ENABLED", kind: kindBool, def: false, usage: "enable the metrics/health endpoint"},
		{key: "metrics.addr", flag: "metrics-addr", env: "METRICS_ADDR", kind: kindString, def: ":9090", usage: "metrics/health listen address"},
		{key: "jobs.enabled", flag: "jobs", env: "JOBS_ENABLED", kind: kindBool, def: false, usage: "enable the async-job endpoints (REST /jobs)"},
		{key: "jobs.store", flag: "jobs-store", env: "JOBS_STORE", kind: kindString, def: "memory", usage: "job store: memory (ephemeral) | bolt (on-disk, survives restart)"},
		{key: "jobs.bolt-path", flag: "jobs-bolt-path", env: "JOBS_BOLT_PATH", kind: kindString, def: "", usage: "bbolt database path (required when jobs.store=bolt)"},
		{key: "jobs.max-concurrent", flag: "jobs-max-concurrent", env: "JOBS_MAX_CONCURRENT", kind: kindInt, def: 0, usage: "max concurrent job executors (0 uses the worker count)"},
		{key: "jobs.queue-size", flag: "jobs-queue-size", env: "JOBS_QUEUE_SIZE", kind: kindInt, def: 128, usage: "pending-job queue depth before backpressure (503)"},
		{key: "jobs.max-input-mb", flag: "jobs-max-input-mb", env: "JOBS_MAX_INPUT_MB", kind: kindInt, def: 0, usage: "reject job requests larger than this many MiB (0 = unlimited)"},
		{key: "jobs.ttl", flag: "jobs-ttl", env: "JOBS_TTL", kind: kindString, def: "1h", usage: "retention for finished jobs, as a Go duration (e.g. 1h)"},
		{key: "idempotency.enabled", flag: "idempotency", env: "IDEMPOTENCY_ENABLED", kind: kindBool, def: false, usage: "enable dedup by idempotency key (REST Idempotency-Key header, MQ envelope idempotencyKey)"},
		{key: "idempotency.ttl", flag: "idempotency-ttl", env: "IDEMPOTENCY_TTL", kind: kindString, def: "24h", usage: "replay window for a cached idempotent result, as a Go duration"},
		{key: "idempotency.max-entries", flag: "idempotency-max-entries", env: "IDEMPOTENCY_MAX_ENTRIES", kind: kindInt, def: 8192, usage: "in-memory idempotency cache bound (LRU eviction beyond this)"},
		{key: "input.allow-local-path", flag: "input-allow-local-path", env: "INPUT_ALLOW_LOCAL_PATH", kind: kindBool, def: false, usage: "accept by-reference data from a local file path (file-read risk; off by default)"},
		{key: "input.allow-url", flag: "input-allow-url", env: "INPUT_ALLOW_URL", kind: kindBool, def: false, usage: "accept by-reference data from a URL (SSRF risk; off by default)"},
		{key: "input.allowed-schemes", flag: "input-allowed-schemes", env: "INPUT_ALLOWED_SCHEMES", kind: kindStringSlice, def: []string{"https"}, usage: "URL schemes accepted for by-reference data"},
		{key: "input.max-mb", flag: "input-max-mb", env: "INPUT_MAX_MB", kind: kindInt, def: 0, usage: "cap a by-reference payload in MiB (0 = unlimited)"},
		{key: "input.spool-dir", flag: "input-spool-dir", env: "INPUT_SPOOL_DIR", kind: kindString, def: "", usage: "directory for fetched-URL spool files (empty = system temp)"},
		{key: "oidc.enabled", flag: "oidc", env: "OIDC_ENABLED", kind: kindBool, def: false, usage: "enable the OIDC 'login with ЭЦП' endpoints (REST /oidc/*)"},
		{key: "oidc.issuer", flag: "oidc-issuer", env: "OIDC_ISSUER", kind: kindString, def: "", usage: "OIDC issuer URL, base for discovery links (required when oidc enabled)"},
		{key: "oidc.key-path", flag: "oidc-key-path", env: "OIDC_KEY_PATH", kind: kindString, def: "", secret: true, usage: "RS256 signing key PEM path (empty = ephemeral in-memory key; JWKS rotates on restart)"},
		{key: "oidc.challenge-ttl", flag: "oidc-challenge-ttl", env: "OIDC_CHALLENGE_TTL", kind: kindString, def: "5m", usage: "challenge validity window, as a Go duration (e.g. 5m)"},
		{key: "oidc.token-ttl", flag: "oidc-token-ttl", env: "OIDC_TOKEN_TTL", kind: kindString, def: "1h", usage: "issued id_token/access_token lifetime, as a Go duration (e.g. 1h)"},
		{key: "oidc.store", flag: "oidc-store", env: "OIDC_STORE", kind: kindString, def: "memory", usage: "challenge store: memory (ephemeral) | bolt (on-disk, survives restart)"},
		{key: "oidc.bolt-path", flag: "oidc-bolt-path", env: "OIDC_BOLT_PATH", kind: kindString, def: "", usage: "bbolt database path (required when oidc.store=bolt)"},
		{key: "oidc.require-ocsp", flag: "oidc-require-ocsp", env: "OIDC_REQUIRE_OCSP", kind: kindBool, def: true, usage: "require a good OCSP status for the signer certificate before issuing tokens"},
		{key: "oidc.audience", flag: "oidc-audience", env: "OIDC_AUDIENCE", kind: kindString, def: "", usage: "default id_token audience when a verify request omits clientId"},
		{key: "oidc.clients", flag: "oidc-clients", env: "OIDC_CLIENTS", kind: kindStringSlice, def: []string{}, secret: true, usage: "relying parties for the browser flow: client_id|secret|redirect_uri[|redirect_uri...]"},
		{key: "qr.enabled", flag: "qr", env: "QR_ENABLED", kind: kindBool, def: false, usage: "enable the eGov Mobile QR signing/auth endpoints (REST /qr/*)"},
		{key: "qr.public-base-url", flag: "qr-public-base-url", env: "QR_PUBLIC_BASE_URL", kind: kindString, def: "", usage: "external base URL for the QR app-facing links (behind a reverse proxy; empty uses X-Forwarded-*/Host)"},
		{key: "qr.default-profile", flag: "qr-default-profile", env: "QR_DEFAULT_PROFILE", kind: kindString, def: "agnostic", usage: "QR profile: agnostic | egov | relay (overridable per request)"},
		{key: "qr.default-mode", flag: "qr-default-mode", env: "QR_DEFAULT_MODE", kind: kindString, def: "sign", usage: "session outcome: sign (return signature) | auth (issue OIDC tokens; requires oidc.enabled)"},
		{key: "qr.session-ttl", flag: "qr-session-ttl", env: "QR_SESSION_TTL", kind: kindString, def: "5m", usage: "session validity window, as a Go duration (e.g. 5m)"},
		{key: "qr.store", flag: "qr-store", env: "QR_STORE", kind: kindString, def: "memory", usage: "session store: memory (ephemeral) | bolt (on-disk, survives restart)"},
		{key: "qr.bolt-path", flag: "qr-bolt-path", env: "QR_BOLT_PATH", kind: kindString, def: "", usage: "bbolt database path (required when qr.store=bolt)"},
		{key: "qr.require-ocsp", flag: "qr-require-ocsp", env: "QR_REQUIRE_OCSP", kind: kindBool, def: false, usage: "require a good OCSP status for the signer certificate before accepting a QR signature"},
		{key: "qr.relay-url", flag: "qr-relay-url", env: "QR_RELAY_URL", kind: kindString, def: "", usage: "upstream eGov QR gateway base URL (required for the relay profile, e.g. https://sigex.kz)"},
		{key: "qr.relay-id", flag: "qr-relay-id", env: "QR_RELAY_ID", kind: kindString, def: "", usage: "optional upstream gateway org id path segment (/api/{id}/egovQr)"},
		{key: "qr.organization", flag: "qr-organization", env: "QR_ORGANIZATION", kind: kindString, def: "", usage: "organization name shown in eGov Mobile (egov/relay profiles)"},
	}
}

// envVar returns the full environment variable name for this entry.
func (e entry) envVar() string { return envPrefix + e.env }

// bind registers this entry's flag on fs and returns a getter for its current
// value (used only when the flag was explicitly set).
func (e entry) bind(fs *flag.FlagSet) func() any {
	switch e.kind {
	case kindBool:
		p := fs.Bool(e.flag, e.def.(bool), e.usage)
		return func() any { return *p }
	case kindInt:
		p := fs.Int(e.flag, e.def.(int), e.usage)
		return func() any { return *p }
	case kindStringSlice:
		p := fs.String(e.flag, strings.Join(e.def.([]string), ","), e.usage+" (comma-separated)")
		return func() any { return splitList(*p) }
	default:
		p := fs.String(e.flag, e.def.(string), e.usage)
		return func() any { return *p }
	}
}

// fromEnv reads this entry from the environment, honoring the <VAR>_FILE
// convention for secrets and any value sourced from a mounted file. It returns
// the parsed value and whether it was present.
func (e entry) fromEnv() (any, bool) {
	if path := os.Getenv(e.envVar() + "_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			return e.parse(strings.TrimSpace(string(data))), true
		}
	}
	if v, ok := os.LookupEnv(e.envVar()); ok {
		return e.parse(v), true
	}
	return nil, false
}

// parse converts a string (env/file) into this entry's typed value.
func (e entry) parse(v string) any {
	switch e.kind {
	case kindBool:
		b, _ := strconv.ParseBool(strings.TrimSpace(v))
		return b
	case kindInt:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	case kindStringSlice:
		return splitList(v)
	default:
		return v
	}
}

// Dump renders the effective configuration with each value's origin, redacting
// secrets. It is safe to print to logs or return from a config-dump command.
func (l *Loaded) Dump() string {
	reg := registry()
	sort.Slice(reg, func(i, j int) bool { return reg[i].key < reg[j].key })

	var b strings.Builder
	for _, e := range reg {
		origin := l.origins[e.key]
		if origin == "" {
			origin = "default"
		}
		val := l.value(e)
		if e.secret {
			val = "***"
		}
		fmt.Fprintf(&b, "%-22s = %-28s (%s)\n", e.key, val, origin)
	}
	return b.String()
}

// value returns the resolved value for an entry as a display string.
func (l *Loaded) value(e entry) string {
	c := l.Config
	switch e.key {
	case "lib.path":
		return c.Lib.Path
	case "lib.version":
		return c.Lib.Version
	case "lib.isolated":
		return strconv.FormatBool(c.Lib.Isolated)
	case "lib.isolation-deps":
		return strings.Join(c.Lib.IsolationDeps, ",")
	case "lib.min-version":
		return c.Lib.MinVersion
	case "lib.compat":
		return c.Lib.Compat
	case "workers":
		return strconv.Itoa(c.Workers)
	case "verify-only":
		return strconv.FormatBool(c.VerifyOnly)
	case "locale":
		return c.Locale
	case "console.enabled":
		return strconv.FormatBool(c.Console.Enabled)
	case "console.sandbox-key":
		return c.Console.SandboxKey
	case "console.sandbox-key-password":
		return c.Console.SandboxKeyPassword
	case "audit.enabled":
		return strconv.FormatBool(c.Audit.Enabled)
	case "audit.path":
		return c.Audit.Path
	case "audit.sync":
		return strconv.FormatBool(c.Audit.Sync)
	case "audit.expose":
		return strconv.FormatBool(c.Audit.Expose)
	case "multisign.enabled":
		return strconv.FormatBool(c.Multisign.Enabled)
	case "multisign.ttl":
		return c.Multisign.TTL
	case "multisign.store":
		return c.Multisign.Store
	case "multisign.bolt-path":
		return c.Multisign.BoltPath
	case "portal.enabled":
		return strconv.FormatBool(c.Portal.Enabled)
	case "certwatch.enabled":
		return strconv.FormatBool(c.CertWatch.Enabled)
	case "certwatch.dir":
		return c.CertWatch.Dir
	case "certwatch.interval":
		return c.CertWatch.Interval
	case "certwatch.warn-from":
		return c.CertWatch.WarnFrom
	case "certwatch.webhook-url":
		return c.CertWatch.WebhookURL
	case "certwatch.check-revocation":
		return strconv.FormatBool(c.CertWatch.CheckRevocation)
	case "challenge.enabled":
		return strconv.FormatBool(c.Challenge.Enabled)
	case "challenge.ttl":
		return c.Challenge.TTL
	case "challenge.store":
		return c.Challenge.Store
	case "challenge.bolt-path":
		return c.Challenge.BoltPath
	case "challenge.require-ocsp":
		return strconv.FormatBool(c.Challenge.RequireOCSP)
	case "receipts.enabled":
		return strconv.FormatBool(c.Receipts.Enabled)
	case "receipts.signed-qr":
		return strconv.FormatBool(c.Receipts.SignedQR)
	case "receipts.issuer":
		return c.Receipts.Issuer
	case "crypto-worker.enabled":
		return strconv.FormatBool(c.CryptoWorker.Enabled)
	case "crypto-worker.processes":
		return strconv.Itoa(c.CryptoWorker.Processes)
	case "crypto-worker.timeout":
		return c.CryptoWorker.Timeout
	case "crypto-worker.max-ops":
		return strconv.Itoa(c.CryptoWorker.MaxOps)
	case "crypto-worker.max-rss-mb":
		return strconv.Itoa(c.CryptoWorker.MaxRSSMB)
	case "crypto-worker.standby":
		return strconv.Itoa(c.CryptoWorker.Standby)
	case "crypto-worker.keep-after-revoked":
		return strconv.FormatBool(c.CryptoWorker.KeepAfterRevoked)
	case "http.enabled":
		return strconv.FormatBool(c.HTTP.Enabled)
	case "http.addr":
		return c.HTTP.Addr
	case "grpc.enabled":
		return strconv.FormatBool(c.GRPC.Enabled)
	case "grpc.addr":
		return c.GRPC.Addr
	case "amqp.url":
		return c.AMQP.URL
	case "amqp.queue":
		return c.AMQP.Queue
	case "amqp.reply-queue":
		return c.AMQP.ReplyQueue
	case "amqp.prefetch":
		return strconv.Itoa(c.AMQP.Prefetch)
	case "kafka.brokers":
		return strings.Join(c.Kafka.Brokers, ",")
	case "kafka.topic":
		return c.Kafka.Topic
	case "kafka.reply-topic":
		return c.Kafka.ReplyTopic
	case "kafka.group":
		return c.Kafka.Group
	case "nats.url":
		return c.NATS.URL
	case "nats.subject":
		return c.NATS.Subject
	case "nats.queue":
		return c.NATS.Queue
	case "nats.reply-subject":
		return c.NATS.ReplySubject
	case "nats.durable":
		return c.NATS.Durable
	case "keys.allow-inline":
		return strconv.FormatBool(c.Keys.AllowInline)
	case "sign.default-timestamp":
		return strconv.FormatBool(c.Sign.DefaultTimestamp)
	case "trust.ca-dir":
		return c.Trust.CADir
	case "trust.fetch-aia":
		return strconv.FormatBool(c.Trust.FetchAIA)
	case "trust.aia-timeout":
		return strconv.Itoa(c.Trust.AIATimeout)
	case "trust.use-rk-registry":
		return strconv.FormatBool(c.Trust.UseRKRegistry)
	case "trust.rk-include-test":
		return strconv.FormatBool(c.Trust.RKIncludeTest)
	case "trust.verify-chain":
		return strconv.FormatBool(c.Trust.VerifyChain)
	case "trust.refresh-interval":
		return c.Trust.RefreshInterval
	case "trust.ocsp-cache":
		return strconv.FormatBool(c.Trust.OCSPCache)
	case "trust.ocsp-cache-ttl":
		return c.Trust.OCSPCacheTTL
	case "trust.ocsp-cache-max-entries":
		return strconv.Itoa(c.Trust.OCSPCacheMaxEntries)
	case "trust.crl-cache":
		return strconv.FormatBool(c.Trust.CRLCache)
	case "trust.crl-spool-dir":
		return c.Trust.CRLSpoolDir
	case "trust.crl-cache-max-mb":
		return strconv.Itoa(c.Trust.CRLCacheMaxMB)
	case "trust.crl-fail-policy":
		return c.Trust.CRLFailPolicy
	case "log.level":
		return c.Log.Level
	case "log.format":
		return c.Log.Format
	case "metrics.enabled":
		return strconv.FormatBool(c.Metrics.Enabled)
	case "metrics.addr":
		return c.Metrics.Addr
	case "jobs.enabled":
		return strconv.FormatBool(c.Jobs.Enabled)
	case "jobs.store":
		return c.Jobs.Store
	case "jobs.bolt-path":
		return c.Jobs.BoltPath
	case "jobs.max-concurrent":
		return strconv.Itoa(c.Jobs.MaxConcurrent)
	case "jobs.queue-size":
		return strconv.Itoa(c.Jobs.QueueSize)
	case "jobs.max-input-mb":
		return strconv.Itoa(c.Jobs.MaxInputMB)
	case "idempotency.enabled":
		return strconv.FormatBool(c.Idempotency.Enabled)
	case "idempotency.ttl":
		return c.Idempotency.TTL
	case "idempotency.max-entries":
		return strconv.Itoa(c.Idempotency.MaxEntries)
	case "jobs.ttl":
		return c.Jobs.TTL
	case "input.allow-local-path":
		return strconv.FormatBool(c.Input.AllowLocalPath)
	case "input.allow-url":
		return strconv.FormatBool(c.Input.AllowURL)
	case "input.allowed-schemes":
		return strings.Join(c.Input.AllowedSchemes, ",")
	case "input.max-mb":
		return strconv.Itoa(c.Input.MaxMB)
	case "input.spool-dir":
		return c.Input.SpoolDir
	case "oidc.enabled":
		return strconv.FormatBool(c.OIDC.Enabled)
	case "oidc.issuer":
		return c.OIDC.Issuer
	case "oidc.key-path":
		return c.OIDC.KeyPath
	case "oidc.challenge-ttl":
		return c.OIDC.ChallengeTTL
	case "oidc.token-ttl":
		return c.OIDC.TokenTTL
	case "oidc.store":
		return c.OIDC.Store
	case "oidc.bolt-path":
		return c.OIDC.BoltPath
	case "oidc.require-ocsp":
		return strconv.FormatBool(c.OIDC.RequireOCSP)
	case "oidc.audience":
		return c.OIDC.Audience
	case "oidc.clients":
		return strconv.Itoa(len(c.OIDC.Clients)) + " client(s)"
	case "qr.enabled":
		return strconv.FormatBool(c.QR.Enabled)
	case "qr.public-base-url":
		return c.QR.PublicBaseURL
	case "qr.default-profile":
		return c.QR.DefaultProfile
	case "qr.default-mode":
		return c.QR.DefaultMode
	case "qr.session-ttl":
		return c.QR.SessionTTL
	case "qr.store":
		return c.QR.Store
	case "qr.bolt-path":
		return c.QR.BoltPath
	case "qr.require-ocsp":
		return strconv.FormatBool(c.QR.RequireOCSP)
	case "qr.relay-url":
		return c.QR.RelayURL
	case "qr.relay-id":
		return c.QR.RelayID
	case "qr.organization":
		return c.QR.Organization
	default:
		return ""
	}
}

// splitList parses a comma-separated list, dropping empty items.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
