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

	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/parsers/toml/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// envPrefix is prepended to every environment variable name.
const envPrefix = "QOLTANBA_"

// Config is the fully resolved service configuration.
type Config struct {
	Lib        LibConfig     `koanf:"lib"`
	Workers    int           `koanf:"workers"`
	VerifyOnly bool          `koanf:"verify-only"`
	HTTP       HTTPConfig    `koanf:"http"`
	GRPC       GRPCConfig    `koanf:"grpc"`
	AMQP       AMQPConfig    `koanf:"amqp"`
	Kafka      KafkaConfig   `koanf:"kafka"`
	NATS       NATSConfig    `koanf:"nats"`
	Keys       KeysConfig    `koanf:"keys"`
	Sign       SignConfig    `koanf:"sign"`
	Trust      TrustConfig   `koanf:"trust"`
	Log        LogConfig     `koanf:"log"`
	Metrics    MetricsConfig `koanf:"metrics"`
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

// KeysConfig configures key handling.
type KeysConfig struct {
	AllowInline bool `koanf:"allow-inline"`
}

// SignConfig configures signing defaults.
type SignConfig struct {
	DefaultTimestamp bool `koanf:"default-timestamp"`
}

// TrustConfig configures the trust store and chain building.
type TrustConfig struct {
	CADir         string `koanf:"ca-dir"`
	FetchAIA      bool   `koanf:"fetch-aia"`       // download missing issuers via AIA
	AIATimeout    int    `koanf:"aia-timeout"`     // per-request timeout, seconds
	UseRKRegistry bool   `koanf:"use-rk-registry"` // preload anchors from the official RK CA registry
	RKIncludeTest bool   `koanf:"rk-include-test"` // include the RK test roots/chains
	VerifyChain   bool   `koanf:"verify-chain"`    // cryptographically validate the chain via Kalkan (incl. GOST)
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
	if c.Log.Format != "text" && c.Log.Format != "json" {
		errs = append(errs, "log.format must be text or json")
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, "log.level must be one of debug|info|warn|error")
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
