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
	case "trust.crl-cache":
		return strconv.FormatBool(c.Trust.CRLCache)
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
	case "jobs.ttl":
		return c.Jobs.TTL
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
