// Package config loads the service configuration from layered sources with a
// fixed precedence: defaults < config file < environment < command-line flags.
// Secrets are read only from the environment or from *_FILE side-files, never
// from flags.
//
// Every setting is declared once in the registry (see registry.go) and from that
// single declaration the three names are derived — the flag (--log-level), the
// environment variable (QOLTANBA_LOG_LEVEL) and the config-file key (log.level).
// This keeps the three surfaces in sync by construction instead of by hand.
package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/parsers/toml/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"

	"github.com/uelnur/qoltanba/internal/pki"
)

// envPrefix is prepended to every environment variable name.
const envPrefix = "QOLTANBA_"

// Config is the fully resolved service configuration.
type Config struct {
	Lib        LibConfig `koanf:"lib"`
	Workers    int       `koanf:"workers"`
	VerifyOnly bool      `koanf:"verify-only"`
	// Locale is the default language for error messages (en|ru|kk). A request may
	// override it per call (REST Accept-Language, gRPC accept-language metadata,
	// MQ envelope locale); the stable error key never changes with the language.
	Locale       string             `koanf:"locale"`
	HTTP         HTTPConfig         `koanf:"http"`
	GRPC         GRPCConfig         `koanf:"grpc"`
	AMQP         AMQPConfig         `koanf:"amqp"`
	Kafka        KafkaConfig        `koanf:"kafka"`
	NATS         NATSConfig         `koanf:"nats"`
	Keys         KeysConfig         `koanf:"keys"`
	CryptoWorker CryptoWorkerConfig `koanf:"crypto-worker"`
	Sign         SignConfig         `koanf:"sign"`
	Trust        TrustConfig        `koanf:"trust"`
	Log          LogConfig          `koanf:"log"`
	Metrics      MetricsConfig      `koanf:"metrics"`
	Jobs         JobsConfig         `koanf:"jobs"`
	Idempotency  IdempotencyConfig  `koanf:"idempotency"`
	Input        InputConfig        `koanf:"input"`
	OIDC         OIDCConfig         `koanf:"oidc"`
	QR           QRConfig           `koanf:"qr"`
	Receipts     ReceiptsConfig     `koanf:"receipts"`
	CertWatch    CertWatchConfig    `koanf:"certwatch"`
	Portal       PortalConfig       `koanf:"portal"`
	Multisign    MultisignConfig    `koanf:"multisign"`
	Audit        AuditConfig        `koanf:"audit"`
	Console      ConsoleConfig      `koanf:"console"`
	Challenge    ChallengeConfig    `koanf:"challenge"`
}

// LibConfig configures the native Kalkan library (BYOL).
type LibConfig struct {
	Path          string   `koanf:"path"`
	Version       string   `koanf:"version"`
	Isolated      bool     `koanf:"isolated"`
	IsolationDeps []string `koanf:"isolation-deps"`
	// MinVersion is the lowest supported library version; a lower detected
	// version is treated as incompatible per Compat policy.
	MinVersion string `koanf:"min-version"`
	// Compat is the startup compatibility policy: strict|warn|off. A self-test
	// failure always blocks regardless of this setting.
	Compat string `koanf:"compat"`
}

// CryptoWorkerConfig runs the crypto operations in child processes instead of the
// service process. The Kalkan library leaks native memory on every operation and
// corrupts its process-global state when it parses a revoked OCSP verdict; a
// later call then aborts the process. Neither can be undone from inside, so the
// service keeps no library of its own and recycles the children on an operation,
// memory or revoked-verdict budget. On by default: without it a long-lived
// service grows until it is killed.
type CryptoWorkerConfig struct {
	Enabled bool `koanf:"enabled"`
	// Processes is how many children serve operations concurrently. Zero uses the
	// worker count.
	Processes int `koanf:"processes"`
	// Timeout bounds one operation, as a Go duration. It is the only way to end a
	// hung call: the native operations have no timeout of their own.
	Timeout string `koanf:"timeout"`
	// MaxOps retires a child after this many operations; a negative value leaves
	// the memory budget as the only bound.
	MaxOps int `koanf:"max-ops"`
	// MaxRSSMB retires a child once its resident memory reaches this size — the
	// bound that answers the library's per-operation leak. Negative disables it.
	MaxRSSMB int `koanf:"max-rss-mb"`
	// Standby is how many pre-warmed children stand ready to take over from a
	// recycled one, so a request never pays for the library load. Each spare costs
	// its own loaded library (tens of MB); zero starts replacements on demand.
	Standby int `koanf:"standby"`
	// KeepAfterRevoked keeps a child that returned a revoked verdict, which is the
	// known corruption trigger. Only for diagnosing the library defect.
	KeepAfterRevoked bool `koanf:"keep-after-revoked"`
}

// ResolveMaxRSSBytes returns the per-child memory ceiling in bytes, defaulting to
// 512 MB; a negative value disables the bound.
func (c CryptoWorkerConfig) ResolveMaxRSSBytes() int64 {
	if c.MaxRSSMB < 0 {
		return -1
	}
	if c.MaxRSSMB == 0 {
		return 512 << 20
	}
	return int64(c.MaxRSSMB) << 20
}

// ResolveTimeout returns the per-operation ceiling, defaulting to 60s for an
// empty, malformed or non-positive value; config.Validate rejects a malformed
// value up front.
func (c CryptoWorkerConfig) ResolveTimeout() time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(c.Timeout))
	if err != nil || d <= 0 {
		return 60 * time.Second
	}
	return d
}

// ResolveProcesses returns the number of children, defaulting to the pool worker
// count.
func (c CryptoWorkerConfig) ResolveProcesses(workers int) int {
	if c.Processes > 0 {
		return c.Processes
	}
	if workers > 0 {
		return workers
	}
	return 1
}

// ReceiptsConfig enables signed verification receipts: the service attests to its
// own verification outcome with the same RS256 service key that signs OIDC
// tokens, so a consumer can file the attestation as audit evidence and verify it
// later against the published JWKS. The key comes from oidc.key-path — one
// service identity, one JWKS — and works with OIDC itself disabled.
type ReceiptsConfig struct {
	Enabled bool `koanf:"enabled"`
	// SignedQR enables QR-carried signed documents (/qr/documents): the service
	// signs a short statement — a permit, a certificate — that a checkpoint can
	// verify by scanning, with the public key and nothing else.
	SignedQR bool `koanf:"signed-qr"`
	// Issuer is the iss claim of a receipt. Empty falls back to oidc.issuer.
	Issuer string `koanf:"issuer"`
}

// ReceiptIssuer resolves the receipt issuer, falling back to the OIDC issuer so a
// deployment that already has an identity does not need to repeat it.
func (c Config) ReceiptIssuer() string {
	if s := strings.TrimSpace(c.Receipts.Issuer); s != "" {
		return s
	}
	return strings.TrimSpace(c.OIDC.Issuer)
}

// ChallengeConfig enables the standalone challenge-response endpoints: a
// single-use nonce the user signs with their ЭЦП to authorize an action. It is
// the same handshake the OIDC login uses, exposed for any business operation
// ("confirm this payment"), so it needs no OIDC issuer or tokens.
type ChallengeConfig struct {
	Enabled bool `koanf:"enabled"`
	// TTL is how long an issued challenge stays usable, as a Go duration.
	TTL string `koanf:"ttl"`
	// Store selects persistence: memory (ephemeral) or bolt (survives restart).
	Store    string `koanf:"store"`
	BoltPath string `koanf:"bolt-path"`
	// RequireOCSP makes every confirmation check the signer certificate for
	// revocation, failing closed when the status cannot be established.
	RequireOCSP bool `koanf:"require-ocsp"`
}

// ChallengeTTL resolves the challenge window, defaulting to 0 so the service
// applies its own default; Validate rejects a malformed value up front.
func (c ChallengeConfig) ChallengeTTL() time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(c.TTL))
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// OCSPCacheTTL resolves the freshness bound for answers without nextUpdate,
// yielding 0 so the cache applies its own default.
func (c TrustConfig) ResolveOCSPCacheTTL() time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(c.OCSPCacheTTL))
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// CertWatchConfig watches certificates an operator cares about (service keys,
// long-lived signer certificates) and reports revocation and upcoming expiry as
// metrics and, optionally, a webhook. Without it those failures are only
// discovered when a signature fails.
type CertWatchConfig struct {
	Enabled bool `koanf:"enabled"`
	// Dir holds the watched certificates, one per file (.pem/.cer/.crt/.der).
	Dir string `koanf:"dir"`
	// Interval between sweeps, as a Go duration.
	Interval string `koanf:"interval"`
	// WarnFrom is how far ahead an upcoming expiry is reported, as a Go duration.
	WarnFrom string `koanf:"warn-from"`
	// WebhookURL receives an event when a certificate's situation changes.
	WebhookURL string `koanf:"webhook-url"`
	// CheckRevocation reaches the OCSP responder on every sweep. Off leaves expiry
	// watching only, for environments without outbound access.
	CheckRevocation bool `koanf:"check-revocation"`
}

// ResolveInterval returns the sweep period, 0 to let the watcher default.
func (c CertWatchConfig) ResolveInterval() time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(c.Interval))
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// ResolveWarnFrom returns the expiry warning window, 0 to let the watcher default.
func (c CertWatchConfig) ResolveWarnFrom() time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(c.WarnFrom))
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// PortalConfig exposes the human verification page: upload a signature, see who
// signed. Off by default — the page takes uploads from anyone who can reach it,
// so publishing it is a deliberate decision.
type PortalConfig struct {
	Enabled bool `koanf:"enabled"`
}

// MultisignConfig tracks documents awaiting several signatures ("waiting for the
// accountant"). Rounds run for days, so the durable store is the realistic choice
// outside a demo.
type MultisignConfig struct {
	Enabled bool `koanf:"enabled"`
	// TTL is how long a round waits before expiring, as a Go duration.
	TTL      string `koanf:"ttl"`
	Store    string `koanf:"store"`     // memory | bolt
	BoltPath string `koanf:"bolt-path"` // required when store=bolt
}

// ResolveTTL returns the session lifetime, 0 to let the service default.
func (c MultisignConfig) ResolveTTL() time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(c.TTL))
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// AuditConfig records signing and verification into a tamper-evident journal:
// hash-chained entries, each signed with the service key, so history cannot be
// rewritten without the key — and an exported copy still contradicts an attempt.
// Off by default: it is a per-operation write, and not every deployment needs an
// operational record.
type AuditConfig struct {
	Enabled bool `koanf:"enabled"`
	// Path is the journal file (JSON Lines, append-only, 0600).
	Path string `koanf:"path"`
	// Sync flushes every entry to disk before the operation returns. Safer against
	// a crash, slower per operation.
	Sync bool `koanf:"sync"`
	// Expose serves /audit/verify and /audit/export over REST. The journal names
	// digests and signer identities, so publishing it is a deliberate decision.
	Expose bool `koanf:"expose"`
}

// ConsoleConfig serves the try-it console and, optionally, a sandbox key for
// producing a demo signature. Both are evaluation aids: the console is a UI on an
// otherwise headless service, and the sandbox signs with a key nobody had to
// supply per request — so both are off by default and the key must be a test
// container.
type ConsoleConfig struct {
	Enabled bool `koanf:"enabled"`
	// SandboxKey is a demo .p12 used by POST /sandbox/sign. Empty disables it.
	SandboxKey string `koanf:"sandbox-key"`
	// SandboxKeyPassword is its container password.
	SandboxKeyPassword string `koanf:"sandbox-key-password"`
}

// HTTPConfig configures the REST transport. Addr may be a TCP address (":8080")
// or a Unix socket ("unix:/run/native.sock").
type HTTPConfig struct {
	Enabled bool   `koanf:"enabled"`
	Addr    string `koanf:"addr"`
}

// GRPCConfig configures the gRPC transport.
type GRPCConfig struct {
	Enabled bool   `koanf:"enabled"`
	Addr    string `koanf:"addr"`
}

// AMQPConfig configures the RabbitMQ transport. It is enabled by supplying a URL
// (no separate enable flag). Reply-to defaults to each message's reply-to
// property; ReplyQueue provides a fixed fallback.
type AMQPConfig struct {
	URL        string `koanf:"url"`
	Queue      string `koanf:"queue"`
	ReplyQueue string `koanf:"reply-queue"`
	Prefetch   int    `koanf:"prefetch"`
}

// Enabled reports whether the RabbitMQ transport is configured.
func (c AMQPConfig) Enabled() bool { return c.URL != "" }

// KafkaConfig configures the Kafka transport. It is enabled by supplying seed
// brokers. A per-record "reply-topic" header overrides ReplyTopic.
type KafkaConfig struct {
	Brokers    []string `koanf:"brokers"`
	Topic      string   `koanf:"topic"`
	ReplyTopic string   `koanf:"reply-topic"`
	Group      string   `koanf:"group"`
}

// Enabled reports whether the Kafka transport is configured.
func (c KafkaConfig) Enabled() bool { return len(c.Brokers) > 0 }

// NATSConfig configures the NATS JetStream transport. It is enabled by supplying
// a URL. Reply defaults to each message's reply subject; ReplySubject is a fixed
// fallback. The backing stream is provisioned by the operator, not the service.
type NATSConfig struct {
	URL          string `koanf:"url"`
	Subject      string `koanf:"subject"`
	Queue        string `koanf:"queue"`
	ReplySubject string `koanf:"reply-subject"`
	Durable      string `koanf:"durable"`
}

// Enabled reports whether the NATS transport is configured.
func (c NATSConfig) Enabled() bool { return c.URL != "" }

// AnyMQEnabled reports whether at least one message-queue transport is configured.
func (c Config) AnyMQEnabled() bool { return c.AMQP.Enabled() || c.Kafka.Enabled() || c.NATS.Enabled() }

// TrustRefreshInterval resolves the effective background anchor-refresh cadence.
// Empty means "auto" — 24h when the RK registry is used, otherwise disabled;
// "0"/"off" disables it explicitly; anything else is parsed as a Go duration.
// A malformed value yields 0 (disabled); config.Validate rejects it up front.
func (c Config) TrustRefreshInterval() time.Duration {
	switch raw := strings.TrimSpace(c.Trust.RefreshInterval); raw {
	case "":
		if c.Trust.UseRKRegistry {
			return 24 * time.Hour
		}
		return 0
	case "0", "off":
		return 0
	default:
		d, err := time.ParseDuration(raw)
		if err != nil {
			return 0
		}
		return d
	}
}

// KeysConfig configures key handling.
type KeysConfig struct {
	AllowInline bool `koanf:"allow-inline"`
}

// SignConfig configures signing defaults.
type SignConfig struct {
	DefaultTimestamp bool `koanf:"default-timestamp"`
	// TSAURL is the timestamp authority used when a request does not name one.
	// Empty leaves the library's built-in default, which is the production
	// responder — it will not stamp a test certificate, so a test environment has
	// to set this.
	TSAURL string `koanf:"tsa-url"`
}

// TrustConfig configures the trust store and chain building.
type TrustConfig struct {
	CADir         string `koanf:"ca-dir"`
	FetchAIA      bool   `koanf:"fetch-aia"`       // download missing issuers via AIA
	AIATimeout    int    `koanf:"aia-timeout"`     // per-request timeout, seconds
	UseRKRegistry bool   `koanf:"use-rk-registry"` // preload anchors from the official RK CA registry
	RKIncludeTest bool   `koanf:"rk-include-test"` // include the RK test roots/chains
	VerifyChain   bool   `koanf:"verify-chain"`    // cryptographically validate the chain via Kalkan (incl. GOST)
	// RefreshInterval is the background anchor-refresh cadence as a Go duration
	// (e.g. "24h"). Empty means "auto": 24h when UseRKRegistry is set, else off.
	// "0"/"off" disables it explicitly. Resolve via TrustRefreshInterval.
	RefreshInterval string `koanf:"refresh-interval"`
	CRLCache        bool   `koanf:"crl-cache"`        // cache CRLs by distribution point for Method=CRL validation
	CRLSpoolDir     string `koanf:"crl-spool-dir"`    // when set, spool CRL bodies to disk (persistent, warm-started); empty = in-memory
	CRLCacheMaxMB   int    `koanf:"crl-cache-max-mb"` // cap on total cached CRL bytes (MiB); 0 = default (256)
	// OCSPCache reuses a recent OCSP answer for the same certificate instead of
	// asking the responder again, and supplies the raw response for stapling.
	OCSPCache bool `koanf:"ocsp-cache"`
	// OCSPCacheTTL bounds an answer that carries no nextUpdate, as a Go duration.
	OCSPCacheTTL string `koanf:"ocsp-cache-ttl"`
	// OCSPCacheMaxEntries bounds the cache; 0 = default (4096).
	OCSPCacheMaxEntries int    `koanf:"ocsp-cache-max-entries"`
	CRLFailPolicy       string `koanf:"crl-fail-policy"` // soft (fall back to OCSP) | hard (fail closed) when CRL is unreliable
	// TSAPolicies restricts which TSA policy OIDs a timestamp may be issued under
	// to count as CAdES-T. Empty enforces nothing: every NUC policy chains to the
	// same anchors, so the choice between them is an operator's call about
	// acceptable algorithms.
	TSAPolicies []string `koanf:"tsa-policies"`
}

// JobsConfig configures the async-job subsystem (REST /jobs endpoints). It is
// off by default; enabling it stands up the manager and its store.
type JobsConfig struct {
	Enabled       bool   `koanf:"enabled"`
	Store         string `koanf:"store"`     // memory | bolt
	BoltPath      string `koanf:"bolt-path"` // required when store=bolt
	MaxConcurrent int    `koanf:"max-concurrent"`
	QueueSize     int    `koanf:"queue-size"`
	MaxInputMB    int    `koanf:"max-input-mb"` // 0 = unlimited
	// TTL is how long a finished job is retained, as a Go duration (e.g. "1h").
	// Resolve via JobsTTL.
	TTL string `koanf:"ttl"`
}

// JobsTTL resolves the retention duration for finished jobs. A malformed or empty
// value yields 0 (the manager then applies its own default); config.Validate
// rejects a malformed value up front.
func (c JobsConfig) JobsTTL() time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(c.TTL))
	if err != nil {
		return 0
	}
	return d
}

// IdempotencyConfig configures request/message dedup by idempotency key, shared
// by the REST (Idempotency-Key header) and MQ (envelope idempotencyKey) transports
// so a retry or an at-least-once redelivery replays the first result instead of
// re-executing. Off by default; node-local (in-memory).
type IdempotencyConfig struct {
	Enabled    bool   `koanf:"enabled"`
	TTL        string `koanf:"ttl"`         // replay window, Go duration (default 24h)
	MaxEntries int    `koanf:"max-entries"` // in-memory cache bound (default 8192)
}

// ResolveTTL returns the replay window, defaulting to 24h for an empty/malformed
// or non-positive value.
func (c IdempotencyConfig) ResolveTTL() time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(c.TTL))
	if err != nil || d <= 0 {
		return 24 * time.Hour
	}
	return d
}

// ResolveMaxEntries returns the cache bound, defaulting to 8192.
func (c IdempotencyConfig) ResolveMaxEntries() int {
	if c.MaxEntries < 1 {
		return 8192
	}
	return c.MaxEntries
}

// InputConfig configures by-reference payloads (DataRef path/URL) for large
// files. Both sources are off by default: a local path is a file-read risk and a
// URL fetch is an SSRF vector, so each is opt-in.
type InputConfig struct {
	AllowLocalPath bool     `koanf:"allow-local-path"`
	AllowURL       bool     `koanf:"allow-url"`
	AllowedSchemes []string `koanf:"allowed-schemes"` // default https
	MaxMB          int      `koanf:"max-mb"`          // 0 = unlimited
	SpoolDir       string   `koanf:"spool-dir"`       // empty = os.TempDir()
}

// Enabled reports whether any by-reference source is turned on (so the resolver
// is worth wiring).
func (c InputConfig) Enabled() bool { return c.AllowLocalPath || c.AllowURL }

// OIDCConfig configures the "login with ЭЦП" OpenID Connect provider (REST
// /oidc/* + discovery). It is off by default; enabling it stands up the flow, an
// RS256 token signer and a challenge store.
type OIDCConfig struct {
	Enabled bool `koanf:"enabled"`
	// Issuer is the OIDC issuer identifier and base URL for discovery links.
	// Required when enabled.
	Issuer string `koanf:"issuer"`
	// KeyPath is the RS256 signing-key PEM file. Empty generates an ephemeral
	// in-memory key (the JWKS kid then rotates on restart, invalidating tokens);
	// a path loads it or generates-and-persists 0600 for a stable kid.
	KeyPath string `koanf:"key-path"`
	// ChallengeTTL and TokenTTL are Go durations (e.g. "5m", "1h"). Resolve via
	// the helpers below.
	ChallengeTTL string `koanf:"challenge-ttl"`
	TokenTTL     string `koanf:"token-ttl"`
	Store        string `koanf:"store"`     // memory | bolt
	BoltPath     string `koanf:"bolt-path"` // required when store=bolt
	RequireOCSP  bool   `koanf:"require-ocsp"`
	Audience     string `koanf:"audience"` // default id_token aud when a verify request omits clientId
	// Clients registers relying parties for the browser-redirect flow, one entry
	// per client as "client_id|secret|redirect_uri[|redirect_uri...]". An empty
	// secret makes the client public, which then must use PKCE. Without any entry
	// only the API grant (challenge/verify) is available.
	Clients []string `koanf:"clients"`
}

// OIDCChallengeTTL resolves the challenge validity window. A malformed or empty
// value yields 0 (the provider applies its own default); Validate rejects a
// malformed value up front.
func (c OIDCConfig) OIDCChallengeTTL() time.Duration { return parseDurationOr0(c.ChallengeTTL) }

// OIDCTokenTTL resolves the issued-token lifetime, with the same semantics as
// OIDCChallengeTTL.
func (c OIDCConfig) OIDCTokenTTL() time.Duration { return parseDurationOr0(c.TokenTTL) }

// QRConfig configures the eGov Mobile QR signing/authorization orchestrator (REST
// /qr/*). Off by default. Three profiles select how the QR reaches eGov Mobile:
// agnostic (generic self-hosted session), egov (we act as the gateway), relay (we
// are a client of an upstream gateway such as SIGEX).
type QRConfig struct {
	Enabled bool `koanf:"enabled"`
	// PublicBaseURL is the externally reachable base URL (behind the consumer's
	// reverse proxy) used to build the app-facing links embedded in the QR. Empty
	// falls back to the request's X-Forwarded-*/Host headers.
	PublicBaseURL  string `koanf:"public-base-url"`
	DefaultProfile string `koanf:"default-profile"` // agnostic | egov | relay
	DefaultMode    string `koanf:"default-mode"`    // sign | auth
	SessionTTL     string `koanf:"session-ttl"`     // Go duration (e.g. "5m")
	Store          string `koanf:"store"`           // memory | bolt
	BoltPath       string `koanf:"bolt-path"`       // required when store=bolt
	RequireOCSP    bool   `koanf:"require-ocsp"`
	RelayURL       string `koanf:"relay-url"` // upstream gateway base (required for relay profile)
	RelayID        string `koanf:"relay-id"`  // optional upstream org id path segment
	Organization   string `koanf:"organization"`
}

// QRSessionTTL resolves the session validity window (empty/malformed → 0, the
// orchestrator's default; Validate rejects a malformed value up front).
func (c QRConfig) QRSessionTTL() time.Duration { return parseDurationOr0(c.SessionTTL) }

// parseDurationOr0 parses a Go duration, returning 0 on empty/malformed input.
func parseDurationOr0(raw string) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0
	}
	return d
}

// LogConfig configures logging.
type LogConfig struct {
	Level  string `koanf:"level"`  // debug | info | warn | error
	Format string `koanf:"format"` // text | json
}

// MetricsConfig configures the observability endpoint, separable from the work
// port.
type MetricsConfig struct {
	Enabled bool   `koanf:"enabled"`
	Addr    string `koanf:"addr"`
}

// Loaded is a resolved config plus the per-key origin (which layer set it), used
// by the dump command.
type Loaded struct {
	Config  Config
	origins map[string]string
}

// Load resolves configuration for the given flag set and argument list. It
// registers the registry's flags on fs, parses args, then merges every layer in
// precedence order.
func Load(fs *flag.FlagSet, args []string) (*Loaded, error) {
	reg := registry()

	configPath := fs.String("config", os.Getenv(envPrefix+"CONFIG"), "path to a config file (yaml/json/toml)")
	getters := make(map[string]func() any, len(reg))
	for _, e := range reg {
		getters[e.key] = e.bind(fs)
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	changed := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { changed[fl.Name] = true })

	k := koanf.New(".")
	origins := map[string]string{}

	// 1. Defaults.
	for _, e := range reg {
		_ = k.Set(e.key, e.def)
		origins[e.key] = "default"
	}

	// 2. Config file (into a scratch instance so only its keys get the "file"
	// origin, then merged over the defaults).
	if *configPath != "" {
		parser, err := parserFor(*configPath)
		if err != nil {
			return nil, err
		}
		fk := koanf.New(".")
		if err := fk.Load(file.Provider(*configPath), parser); err != nil {
			return nil, fmt.Errorf("config: load %s: %w", *configPath, err)
		}
		for _, key := range fk.Keys() {
			_ = k.Set(key, fk.Get(key))
			origins[key] = "file"
		}
	}

	// 3. Environment (+ *_FILE secret side-files).
	for _, e := range reg {
		if v, ok := e.fromEnv(); ok {
			_ = k.Set(e.key, v)
			origins[e.key] = "env"
		}
	}

	// 4. Flags — only those explicitly set on the command line win.
	for _, e := range reg {
		if changed[e.flag] {
			_ = k.Set(e.key, getters[e.key]())
			origins[e.key] = "flag"
		}
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, fmt.Errorf("config: decode: %w", err)
	}
	return &Loaded{Config: cfg, origins: origins}, nil
}

// Validate reports configuration errors as a combined list, so operators see
// every problem at once rather than one per run.
func (l *Loaded) Validate() error {
	var errs []string
	c := l.Config
	// The library is required in every mode: verify-only still verifies via Kalkan.
	if c.Lib.Path == "" {
		errs = append(errs, "lib.path is required (path to libkalkancryptwr-64.so)")
	}
	if c.Workers < 1 {
		errs = append(errs, "workers must be >= 1")
	}
	if c.Workers > 1 && !c.Lib.Isolated {
		errs = append(errs, "workers > 1 requires lib.isolated=true (instances share crypto state otherwise)")
	}
	switch strings.ToLower(c.Lib.Compat) {
	case "strict", "warn", "off":
	default:
		errs = append(errs, "lib.compat must be one of strict|warn|off")
	}
	if c.AMQP.Enabled() && c.AMQP.Queue == "" {
		errs = append(errs, "amqp.queue is required when amqp.url is set")
	}
	if c.Kafka.Enabled() {
		if c.Kafka.Topic == "" {
			errs = append(errs, "kafka.topic is required when kafka.brokers is set")
		}
		if c.Kafka.Group == "" {
			errs = append(errs, "kafka.group is required when kafka.brokers is set")
		}
	}
	if c.NATS.Enabled() {
		if c.NATS.Subject == "" {
			errs = append(errs, "nats.subject is required when nats.url is set")
		}
		if c.NATS.Durable == "" {
			errs = append(errs, "nats.durable is required when nats.url is set")
		}
	}
	if c.CryptoWorker.Enabled {
		if raw := strings.TrimSpace(c.CryptoWorker.Timeout); raw != "" {
			if _, err := time.ParseDuration(raw); err != nil {
				errs = append(errs, "crypto-worker.timeout must be a Go duration (e.g. 60s)")
			}
		}
		if c.CryptoWorker.Processes < 0 {
			errs = append(errs, "crypto-worker.processes must be >= 0")
		}
		if c.CryptoWorker.Standby < 0 {
			errs = append(errs, "crypto-worker.standby must be >= 0")
		}
	}
	if c.Trust.OCSPCache {
		if raw := strings.TrimSpace(c.Trust.OCSPCacheTTL); raw != "" {
			if _, err := time.ParseDuration(raw); err != nil {
				errs = append(errs, "trust.ocsp-cache-ttl must be a Go duration (e.g. 10m)")
			}
		}
	}
	if c.Audit.Enabled && strings.TrimSpace(c.Audit.Path) == "" {
		errs = append(errs, "audit.path is required when audit.enabled")
	}
	if c.Multisign.Enabled {
		if raw := strings.TrimSpace(c.Multisign.TTL); raw != "" {
			if _, err := time.ParseDuration(raw); err != nil {
				errs = append(errs, "multisign.ttl must be a Go duration (e.g. 168h)")
			}
		}
		switch c.Multisign.Store {
		case "", "memory":
		case "bolt":
			if strings.TrimSpace(c.Multisign.BoltPath) == "" {
				errs = append(errs, "multisign.bolt-path is required when multisign.store=bolt")
			}
		default:
			errs = append(errs, "multisign.store must be memory or bolt")
		}
	}
	if c.CertWatch.Enabled {
		if strings.TrimSpace(c.CertWatch.Dir) == "" {
			errs = append(errs, "certwatch.dir is required when certwatch.enabled")
		}
		for key, raw := range map[string]string{
			"certwatch.interval":  c.CertWatch.Interval,
			"certwatch.warn-from": c.CertWatch.WarnFrom,
		} {
			if raw = strings.TrimSpace(raw); raw != "" {
				if _, err := time.ParseDuration(raw); err != nil {
					errs = append(errs, key+" must be a Go duration (e.g. 6h, 720h)")
				}
			}
		}
	}
	if c.Challenge.Enabled {
		if raw := strings.TrimSpace(c.Challenge.TTL); raw != "" {
			if _, err := time.ParseDuration(raw); err != nil {
				errs = append(errs, "challenge.ttl must be a Go duration (e.g. 5m)")
			}
		}
		switch c.Challenge.Store {
		case "", "memory":
		case "bolt":
			if strings.TrimSpace(c.Challenge.BoltPath) == "" {
				errs = append(errs, "challenge.bolt-path is required when challenge.store=bolt")
			}
		default:
			errs = append(errs, "challenge.store must be memory or bolt")
		}
	}
	if c.Log.Format != "text" && c.Log.Format != "json" {
		errs = append(errs, "log.format must be text or json")
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, "log.level must be one of debug|info|warn|error")
	}
	if raw := strings.TrimSpace(c.Trust.RefreshInterval); raw != "" && raw != "0" && raw != "off" {
		if _, err := time.ParseDuration(raw); err != nil {
			errs = append(errs, "trust.refresh-interval must be a Go duration (e.g. 24h), empty, 0 or off")
		}
	}
	for _, p := range c.Trust.TSAPolicies {
		if !pki.IsTSAPolicy(strings.TrimSpace(p)) {
			errs = append(errs, "trust.tsa-policies: "+p+" is not a NUC TSA policy OID (arc "+pki.TSAPolicyArc+")")
		}
	}
	switch strings.TrimSpace(c.Trust.CRLFailPolicy) {
	case "", "soft", "hard":
	default:
		errs = append(errs, "trust.crl-fail-policy must be soft or hard")
	}
	if c.Jobs.Enabled {
		switch c.Jobs.Store {
		case "memory":
		case "bolt":
			if strings.TrimSpace(c.Jobs.BoltPath) == "" {
				errs = append(errs, "jobs.bolt-path is required when jobs.store=bolt")
			}
		default:
			errs = append(errs, "jobs.store must be memory or bolt")
		}
		if raw := strings.TrimSpace(c.Jobs.TTL); raw != "" {
			if _, err := time.ParseDuration(raw); err != nil {
				errs = append(errs, "jobs.ttl must be a Go duration (e.g. 1h)")
			}
		}
	}
	if c.OIDC.Enabled {
		if strings.TrimSpace(c.OIDC.Issuer) == "" {
			errs = append(errs, "oidc.issuer is required when oidc.enabled (the OIDC issuer URL)")
		}
		switch c.OIDC.Store {
		case "", "memory":
		case "bolt":
			if strings.TrimSpace(c.OIDC.BoltPath) == "" {
				errs = append(errs, "oidc.bolt-path is required when oidc.store=bolt")
			}
		default:
			errs = append(errs, "oidc.store must be memory or bolt")
		}
		for _, d := range []struct{ name, raw string }{
			{"oidc.challenge-ttl", c.OIDC.ChallengeTTL},
			{"oidc.token-ttl", c.OIDC.TokenTTL},
		} {
			if raw := strings.TrimSpace(d.raw); raw != "" {
				if _, err := time.ParseDuration(raw); err != nil {
					errs = append(errs, d.name+" must be a Go duration (e.g. 5m)")
				}
			}
		}
	}
	if c.QR.Enabled {
		switch c.QR.DefaultProfile {
		case "", "agnostic", "egov":
		case "relay":
			if strings.TrimSpace(c.QR.RelayURL) == "" {
				errs = append(errs, "qr.relay-url is required when qr.default-profile=relay")
			}
		default:
			errs = append(errs, "qr.default-profile must be agnostic, egov or relay")
		}
		switch c.QR.DefaultMode {
		case "", "sign", "auth":
		default:
			errs = append(errs, "qr.default-mode must be sign or auth")
		}
		if c.QR.DefaultMode == "auth" && !c.OIDC.Enabled {
			errs = append(errs, "qr.default-mode=auth requires oidc.enabled (shared token signer)")
		}
		switch c.QR.Store {
		case "", "memory":
		case "bolt":
			if strings.TrimSpace(c.QR.BoltPath) == "" {
				errs = append(errs, "qr.bolt-path is required when qr.store=bolt")
			}
		default:
			errs = append(errs, "qr.store must be memory or bolt")
		}
		if raw := strings.TrimSpace(c.QR.SessionTTL); raw != "" {
			if _, err := time.ParseDuration(raw); err != nil {
				errs = append(errs, "qr.session-ttl must be a Go duration (e.g. 5m)")
			}
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
}

// parserFor selects a koanf parser by file extension.
func parserFor(path string) (koanf.Parser, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return yaml.Parser(), nil
	case ".json":
		return json.Parser(), nil
	case ".toml":
		return toml.Parser(), nil
	default:
		return nil, fmt.Errorf("config: unsupported file type %q (use yaml/json/toml)", filepath.Ext(path))
	}
}
