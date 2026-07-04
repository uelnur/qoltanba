// Command qoltanba is the entry point of the digital-signature service
// built on the native Kalkan library. It resolves configuration (defaults <
// file < env < flags), brings up the driver pool, builds the domain service and
// serves the selected transport.
//
// Usage:
//
//	qoltanba [flags]            # serve (REST) — needs -http
//	qoltanba <op>  [flags]      # CLI transport: JSON on stdin → stdout
//	                                  # op ∈ sign|verify|extract|cert-info|cert-validate
//	qoltanba config-dump [flags]  # print the effective config (secrets masked)
//	qoltanba config-check [flags] # validate config, exit non-zero on error
//	qoltanba lib-check [flags]    # check BYOL library compatibility (add -json)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	grpclib "google.golang.org/grpc"

	"github.com/uelnur/qoltanba/internal/aia"
	"github.com/uelnur/qoltanba/internal/compat"
	"github.com/uelnur/qoltanba/internal/config"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/crl"
	"github.com/uelnur/qoltanba/internal/jobs"
	"github.com/uelnur/qoltanba/internal/keysource"
	"github.com/uelnur/qoltanba/internal/metrics"
	"github.com/uelnur/qoltanba/internal/native"
	"github.com/uelnur/qoltanba/internal/pki"
	"github.com/uelnur/qoltanba/internal/transport/amqp"
	"github.com/uelnur/qoltanba/internal/transport/cli"
	"github.com/uelnur/qoltanba/internal/transport/dispatch"
	grpctransport "github.com/uelnur/qoltanba/internal/transport/grpc"
	"github.com/uelnur/qoltanba/internal/transport/kafka"
	"github.com/uelnur/qoltanba/internal/transport/mq"
	natstransport "github.com/uelnur/qoltanba/internal/transport/nats"
	"github.com/uelnur/qoltanba/internal/transport/rest"
	"github.com/uelnur/qoltanba/internal/trust"
)

// version is the service build version, overridable at link time.
var version = "dev"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	// A leading non-flag token selects a subcommand; otherwise we serve.
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, rest := args[0], args[1:]
		switch {
		case cmd == "config-dump":
			return runDump(rest)
		case cmd == "config-check":
			return runCheck(rest)
		case cmd == "lib-check":
			return runLibCheck(rest)
		case isOp(cmd):
			return runCLI(cmd, rest)
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q (ops: %s; or config-dump/config-check/lib-check)\n",
				cmd, strings.Join(cli.Ops, "|"))
			return 2
		}
	}
	return runServe(args)
}

// loadConfig parses a fresh flag set for the given args.
func loadConfig(name string, args []string) (*config.Loaded, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return config.Load(fs, args)
}

func runDump(args []string) int {
	l, err := loadConfig("config-dump", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Print(l.Dump())
	return 0
}

func runCheck(args []string) int {
	l, err := loadConfig("config-check", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := l.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("configuration OK")
	return 0
}

// runLibCheck opens the consumer-supplied library, runs the compatibility
// assessment (version, capabilities, smoke self-test) and prints a detailed
// report. It exits non-zero when the library is incompatible, independent of the
// configured startup policy — this command is a diagnostic. Add -json for a
// machine-readable report.
func runLibCheck(args []string) int {
	args, asJSON := extractBoolFlag(args, "json")
	l, err := loadConfig("lib-check", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := l.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	pool, report, err := openLibrary(l.Config)
	if err != nil {
		// The library could not even be loaded (missing file, bitness, dependency,
		// no KC_GetFunctionList): report the load failure itself.
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = pool.Close() }()

	if asJSON {
		b, jerr := report.JSON()
		if jerr != nil {
			fmt.Fprintln(os.Stderr, jerr)
			return 1
		}
		fmt.Println(string(b))
	} else {
		fmt.Print(report.Text())
	}
	if !report.Compatible() {
		return 1
	}
	return 0
}

func runCLI(op string, args []string) int {
	l, err := loadConfig(op, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := l.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	svc, closer, _, _, err := buildService(l.Config, discardLogger(), nil) // CLI is one-shot: no metrics
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer closer()
	return cli.Run(context.Background(), svc, op, os.Stdin, os.Stdout)
}

// extractBoolFlag removes a bare boolean flag (e.g. -json / --json) from args
// before the config flag set parses them, and reports whether it was present.
// The config flag set is strict about unknown flags, so command-specific flags
// are pulled out here.
func extractBoolFlag(args []string, name string) ([]string, bool) {
	found := false
	out := args[:0:0]
	for _, a := range args {
		if a == "-"+name || a == "--"+name {
			found = true
			continue
		}
		out = append(out, a)
	}
	return out, found
}

func runServe(args []string) int {
	l, err := loadConfig("serve", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := l.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	cfg := l.Config
	log := newLogger(cfg.Log)

	if !cfg.HTTP.Enabled && !cfg.GRPC.Enabled && !cfg.AnyMQEnabled() {
		log.Error("no transport enabled: pass -http/-grpc or an MQ URL (-amqp-url/-kafka-brokers/-nats-url) to serve, or run a CLI op")
		return 2
	}

	rec := metrics.New()
	svc, closer, refresher, report, err := buildService(cfg, log, rec)
	if err != nil {
		log.Error("startup failed", "error", err)
		return 1
	}
	defer closer()
	caps := report.Caps
	log.Info("library ready", "version", caps.Version, "poolSize", caps.PoolSize,
		"verifyOnly", cfg.VerifyOnly, "compat", report.VerdictString(), "selfTest", report.SelfTest.OK)

	status := func() rest.StatusInfo {
		return rest.StatusInfo{
			Service: "qoltanba", Version: version, LibVersion: caps.Version,
			VerifyOnly: cfg.VerifyOnly, PoolSize: caps.PoolSize, Capabilities: caps,
			SelfTest: report.SelfTest.OK, Compat: report.VerdictString(),
			TrustRefresh: refresher.Status(),
		}
	}
	ready := func() bool { return true } // library loaded, self-tested and gated before serving

	mgr, err := buildJobs(cfg, svc, log)
	if err != nil {
		log.Error("job subsystem setup failed", "error", err)
		return 1
	}

	return serve(cfg, svc, mgr, refresher, rec, ready, status, log)
}

// buildJobs constructs the async-job manager when enabled, wiring its executor to
// the shared operation router so jobs run the exact same contract as the sync
// endpoints. It returns a nil manager (no error) when jobs are disabled.
func buildJobs(cfg config.Config, svc *core.Service, log *slog.Logger) (*jobs.Manager, error) {
	if !cfg.Jobs.Enabled {
		return nil, nil
	}
	var store jobs.Store
	switch cfg.Jobs.Store {
	case "bolt":
		bs, err := jobs.OpenBoltStore(cfg.Jobs.BoltPath)
		if err != nil {
			return nil, fmt.Errorf("open job store: %w", err)
		}
		store = bs
	default:
		store = jobs.NewMemStore()
	}

	workers := cfg.Jobs.MaxConcurrent
	if workers < 1 {
		workers = cfg.Workers // default to the crypto pool size
	}
	exec := func(ctx context.Context, op string, req json.RawMessage) (any, error) {
		return dispatch.Handle(ctx, svc, op, req)
	}
	mgr := jobs.New(store, exec, dispatch.Valid, jobs.Config{
		Workers:       workers,
		QueueSize:     cfg.Jobs.QueueSize,
		TTL:           cfg.Jobs.JobsTTL(),
		MaxInputBytes: cfg.Jobs.MaxInputMB << 20,
	}, jobs.WithLogger(log), jobs.WithWebhook(jobWebhook(log)))
	return mgr, nil
}

// jobWebhook delivers a terminal job notification by POSTing the client-safe view
// as JSON to the caller's callbackUrl. It is best-effort: a delivery failure is
// logged, not retried. The view carries no secrets.
func jobWebhook(log *slog.Logger) jobs.Webhook {
	return func(ctx context.Context, url string, v jobs.View) {
		body, err := json.Marshal(v)
		if err != nil {
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			log.Warn("job webhook build failed", "job", v.ID, "error", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Warn("job webhook delivery failed", "job", v.ID, "error", err)
			return
		}
		_ = resp.Body.Close()
	}
}

// serve starts every enabled transport (REST, gRPC, optional separate metrics
// port) and drains them gracefully on a shutdown signal.
func serve(cfg config.Config, svc *core.Service, mgr *jobs.Manager, refresher *trust.Refresher, rec *metrics.Recorder, ready func() bool, status func() rest.StatusInfo, log *slog.Logger) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The async-job manager shares the serve context: its pool drains when ctx is
	// canceled. It is served over REST, so warn if enabled without the HTTP port.
	if mgr != nil {
		if !cfg.HTTP.Enabled {
			log.Warn("jobs enabled but the REST transport is off: /jobs endpoints will not be reachable")
		}
		if err := mgr.Start(ctx); err != nil {
			log.Error("job manager start failed", "error", err)
			return 1
		}
	}

	// Background trust-anchor refresh drains with ctx. A resolved interval of 0
	// (default without the RK registry, or an explicit 0/off) makes Run a no-op.
	if interval := cfg.TrustRefreshInterval(); interval > 0 {
		log.Info("trust auto-refresh enabled", "interval", interval.String())
		go refresher.Run(ctx, interval)
	}

	obs := rest.Observability(ready, status)
	var shutdowns []func(context.Context)

	if cfg.HTTP.Enabled {
		var restOpts []rest.Option
		if mgr != nil {
			restOpts = append(restOpts, rest.WithJobs(mgr))
		}
		work := http.NewServeMux()
		work.Handle("/", rec.InstrumentHTTP("rest", rest.New(svc, restOpts...).Routes()))
		mountObs(work, obs)
		work.Handle("GET /metrics", rec.Handler())

		ln, err := listen(cfg.HTTP.Addr)
		if err != nil {
			log.Error("listen", "addr", cfg.HTTP.Addr, "error", err)
			return 1
		}
		srv := &http.Server{Handler: work, ReadHeaderTimeout: 10 * time.Second}
		shutdowns = append(shutdowns, func(c context.Context) { _ = srv.Shutdown(c) })
		go func() {
			log.Info("serving REST", "addr", cfg.HTTP.Addr)
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("REST server", "error", err)
				stop()
			}
		}()
	}

	// Separate observability/metrics port. Runs whenever metrics are enabled and it
	// is not already the work port — so gRPC/MQ-only deployments expose /metrics too.
	if cfg.Metrics.Enabled && (!cfg.HTTP.Enabled || cfg.Metrics.Addr != cfg.HTTP.Addr) {
		obsMux := http.NewServeMux()
		mountObs(obsMux, obs)
		obsMux.Handle("GET /metrics", rec.Handler())
		mln, err := listen(cfg.Metrics.Addr)
		if err != nil {
			log.Error("listen metrics", "addr", cfg.Metrics.Addr, "error", err)
			return 1
		}
		obsSrv := &http.Server{Handler: obsMux, ReadHeaderTimeout: 10 * time.Second}
		shutdowns = append(shutdowns, func(c context.Context) { _ = obsSrv.Shutdown(c) })
		go func() {
			log.Info("serving health/metrics", "addr", cfg.Metrics.Addr)
			if err := obsSrv.Serve(mln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics server", "error", err)
			}
		}()
	}

	if cfg.GRPC.Enabled {
		ln, err := listen(cfg.GRPC.Addr)
		if err != nil {
			log.Error("listen grpc", "addr", cfg.GRPC.Addr, "error", err)
			return 1
		}
		gs := grpclib.NewServer(grpclib.UnaryInterceptor(rec.UnaryInterceptor()))
		grpctransport.New(svc).Register(gs)
		shutdowns = append(shutdowns, func(context.Context) { gs.GracefulStop() })
		go func() {
			log.Info("serving gRPC", "addr", cfg.GRPC.Addr)
			if err := gs.Serve(ln); err != nil {
				log.Error("gRPC server", "error", err)
				stop()
			}
		}()
	}

	// MQ consumers self-drain when ctx is canceled; a startup/runtime fault stops
	// the whole service. A shared processor fans out to every broker.
	var mqWG sync.WaitGroup
	if cfg.AnyMQEnabled() {
		startMQ(ctx, &mqWG, cfg, mq.NewProcessor(svc, rec), log, stop)
	}

	<-ctx.Done()
	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, sd := range shutdowns {
		sd(shutCtx)
	}
	mqWG.Wait()
	if mgr != nil {
		mgr.Wait() // workers drain on ctx cancel
		if err := mgr.Close(); err != nil {
			log.Warn("job store close", "error", err)
		}
	}
	return 0
}

// mqConsumer is the shared shape of every message-queue transport: a blocking
// serve loop that drains and returns when ctx is canceled.
type mqConsumer interface {
	Run(ctx context.Context) error
}

// startMQ launches every configured MQ consumer on its own goroutine, tracking
// them in wg. A consumer returning a non-nil error (dial/setup failure or a fatal
// runtime fault) stops the whole service, mirroring the REST/gRPC serve loops.
func startMQ(ctx context.Context, wg *sync.WaitGroup, cfg config.Config, proc *mq.Processor, log *slog.Logger, stop func()) {
	launch := func(name string, c mqConsumer) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Info("serving MQ", "transport", name)
			if err := c.Run(ctx); err != nil {
				log.Error("MQ consumer", "transport", name, "error", err)
				stop()
			}
		}()
	}

	if cfg.AMQP.Enabled() {
		launch("amqp", amqp.New(proc, amqp.Config{
			URL: cfg.AMQP.URL, Queue: cfg.AMQP.Queue, ReplyQueue: cfg.AMQP.ReplyQueue, Prefetch: cfg.AMQP.Prefetch,
		}, cfg.Workers, log))
	}
	if cfg.Kafka.Enabled() {
		launch("kafka", kafka.New(proc, kafka.Config{
			Brokers: cfg.Kafka.Brokers, Topic: cfg.Kafka.Topic, ReplyTopic: cfg.Kafka.ReplyTopic, Group: cfg.Kafka.Group,
		}, cfg.Workers, log))
	}
	if cfg.NATS.Enabled() {
		launch("nats", natstransport.New(proc, natstransport.Config{
			URL: cfg.NATS.URL, Subject: cfg.NATS.Subject, Queue: cfg.NATS.Queue,
			ReplySubject: cfg.NATS.ReplySubject, Durable: cfg.NATS.Durable,
		}, cfg.Workers, log))
	}
}

// openLibrary loads the driver pool and assesses BYOL compatibility (version,
// capability map, mandatory smoke self-test) WITHOUT gating. It errors only when
// the library cannot be loaded at all; a loaded-but-incompatible library returns
// a report whose verdict the caller acts on. Shared by buildService (which
// gates) and lib-check (which only reports).
func openLibrary(cfg config.Config) (*native.Pool, compat.Report, error) {
	pool, err := native.Open(native.Config{
		WrapperPath:   cfg.Lib.Path,
		PoolSize:      cfg.Workers,
		Isolated:      cfg.Lib.Isolated,
		IsolationDeps: cfg.Lib.IsolationDeps,
		Version:       cfg.Lib.Version,
	})
	if err != nil {
		return nil, compat.Report{}, fmt.Errorf("load driver: %w", err)
	}
	self, err := pool.SelfTest(context.Background())
	if err != nil {
		_ = pool.Close()
		return nil, compat.Report{}, fmt.Errorf("self-test: %w", err)
	}
	report := compat.Evaluate(cfg.Lib.Path, pool.Capabilities(), self, compat.Requirements{
		MinVersion:  cfg.Lib.MinVersion,
		RequireSign: !cfg.VerifyOnly,
	})
	return pool, report, nil
}

// buildService opens the driver pool, enforces the compatibility policy, and
// assembles the domain service with its infrastructure (key source, trust
// store). It refuses to build the service when the library is incompatible under
// the configured policy (a self-test failure always refuses).
func buildService(cfg config.Config, log *slog.Logger, rec *metrics.Recorder) (*core.Service, func(), *trust.Refresher, compat.Report, error) {
	pool, report, err := openLibrary(cfg)
	if err != nil {
		return nil, nil, nil, compat.Report{}, err
	}
	rec.BindPool(pool.Stats)
	policy, _ := compat.ParsePolicy(cfg.Lib.Compat) // validated by config.Validate
	if log != nil {
		logReport(log, report, policy)
	}
	if report.MustRefuse(policy) {
		_ = pool.Close()
		return nil, nil, nil, report, fmt.Errorf("library incompatible (policy=%s), refusing to start:\n%s",
			policy, report.Text())
	}

	store, err := trust.LoadDir(cfg.Trust.CADir)
	if err != nil {
		_ = pool.Close()
		return nil, nil, nil, report, fmt.Errorf("load trust store: %w", err)
	}
	fetch := trust.HTTPFetcher(time.Duration(cfg.Trust.AIATimeout) * time.Second)
	var refs []pki.CACertRef
	if cfg.Trust.UseRKRegistry {
		refs = pki.CACertificatesFor(cfg.Trust.RKIncludeTest)
		errs := store.LoadRegistry(context.Background(), refs, fetch)
		if len(errs) > 0 && log != nil {
			log.Warn("RK registry: some CA certificates could not be loaded", "failed", len(errs), "total", len(refs))
		}
	}
	// The refresher rebuilds anchors in the background (started by serve when the
	// resolved interval is > 0). refs is empty when the registry is off, so it then
	// only re-scans the CA directory.
	refresher := trust.NewRefresher(store, cfg.Trust.CADir, refs, fetch, log)
	rec.BindTrust(store.Count)

	opts := []core.Option{
		core.WithTrustStore(store),
		core.WithVerifyOnly(cfg.VerifyOnly),
	}
	if !cfg.VerifyOnly {
		opts = append(opts, core.WithKeySource(keysource.New(keysource.WithInline(cfg.Keys.AllowInline))))
		opts = append(opts, core.WithDefaultTimestamp(cfg.Sign.DefaultTimestamp))
	}
	if cfg.Trust.FetchAIA {
		opts = append(opts, core.WithIssuerFetcher(aia.New(time.Duration(cfg.Trust.AIATimeout)*time.Second)))
	}
	if cfg.Trust.CRLCache {
		cache := crl.New(time.Duration(cfg.Trust.AIATimeout) * time.Second)
		rec.BindCRL(cache.Stats)
		opts = append(opts, core.WithCRLSource(cache))
	}
	if cfg.Trust.VerifyChain {
		opts = append(opts, core.WithChainVerification(true))
	}
	svc := core.New(pool, opts...)
	closer := func() {
		if err := pool.Close(); err != nil && log != nil {
			log.Warn("driver close", "error", err)
		}
	}
	return svc, closer, refresher, report, nil
}

// logReport emits the compatibility assessment at a level matched to the
// verdict, plus one line per non-passing check. Secrets never appear here (the
// report carries only version, capabilities and self-test outcome).
func logReport(log *slog.Logger, r compat.Report, p compat.Policy) {
	lvl := slog.LevelInfo
	switch r.Verdict() {
	case compat.StatusFail:
		lvl = slog.LevelError
	case compat.StatusWarn:
		lvl = slog.LevelWarn
	}
	log.Log(context.Background(), lvl, "library compatibility",
		"verdict", r.VerdictString(), "version", r.Version,
		"poolSize", r.PoolSize, "selfTest", r.SelfTest.OK, "policy", p.String())
	for _, c := range r.Checks {
		if c.Status == compat.StatusPass {
			continue
		}
		clvl := slog.LevelWarn
		if c.Status == compat.StatusFail {
			clvl = slog.LevelError
		}
		log.Log(context.Background(), clvl, "compatibility check",
			"name", c.Name, "status", c.Status.String(), "detail", c.Detail)
	}
}

// mountObs adds the health/status routes to the work mux.
func mountObs(work *http.ServeMux, obs http.Handler) {
	for _, p := range []string{"/healthz", "/readyz", "/statusz"} {
		work.Handle("GET "+p, obs)
	}
}

// listen opens a TCP or Unix-socket listener. "unix:/path" selects a socket;
// otherwise the value is a TCP address.
func listen(addr string) (net.Listener, error) {
	if path, ok := strings.CutPrefix(addr, "unix:"); ok {
		_ = os.Remove(path) // stale socket from a previous run
		return net.Listen("unix", path)
	}
	return net.Listen("tcp", addr)
}

func isOp(cmd string) bool {
	for _, op := range cli.Ops {
		if op == cmd {
			return true
		}
	}
	return false
}

func newLogger(c config.LogConfig) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slogLevel(c.Level)}
	if c.Format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func slogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
