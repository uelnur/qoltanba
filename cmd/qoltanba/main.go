// Command qoltanba is the entry point of the digital-signature service
// built on the native Kalkan library. It resolves configuration (defaults <
// file < env < flags), brings up the driver pool, builds the domain service and
// serves the selected transport.
//
// Usage:
//
//	qoltanba [flags]            # serve (REST) — needs -http
//	qoltanba <op>  [flags]      # CLI transport: JSON on stdin → stdout
//	                                  # add -fail-invalid to exit 2 when a verification is negative
//	                                  # op ∈ sign|verify|extract|cert-info|cert-validate
//	qoltanba config-dump [flags]  # print the effective config (secrets masked)
//	qoltanba config-check [flags] # validate config, exit non-zero on error
//	qoltanba lib-check [flags]    # check BYOL library compatibility (add -json)
//	qoltanba crypto-worker …      # internal: the child process that runs the crypto operations
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
	"github.com/uelnur/qoltanba/internal/audit"
	"github.com/uelnur/qoltanba/internal/certwatch"
	"github.com/uelnur/qoltanba/internal/challenge"
	"github.com/uelnur/qoltanba/internal/compat"
	"github.com/uelnur/qoltanba/internal/config"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/crl"
	"github.com/uelnur/qoltanba/internal/cryptoworker"
	"github.com/uelnur/qoltanba/internal/dataref"
	"github.com/uelnur/qoltanba/internal/idempotency"
	"github.com/uelnur/qoltanba/internal/jobs"
	"github.com/uelnur/qoltanba/internal/keysource"
	"github.com/uelnur/qoltanba/internal/metrics"
	"github.com/uelnur/qoltanba/internal/multisign"
	"github.com/uelnur/qoltanba/internal/native"
	"github.com/uelnur/qoltanba/internal/ocspcache"
	"github.com/uelnur/qoltanba/internal/oidc"
	"github.com/uelnur/qoltanba/internal/pki"
	"github.com/uelnur/qoltanba/internal/qr"
	"github.com/uelnur/qoltanba/internal/signedqr"
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
		case cmd == "crypto-worker":
			return runCryptoWorker(rest)
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
	// A pipeline gate wants a non-zero exit when the artifact does not verify,
	// which is not the API default (an invalid signature is a valid answer).
	args, failInvalid := extractBoolFlag(args, "fail-invalid")
	l, err := loadConfig(op, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := l.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	cfg := l.Config
	// The CLI runs one operation and exits, so neither the leak nor the corrupted
	// state gets a later call to hurt — a child process would only cost a second
	// library load per invocation.
	cfg.CryptoWorker.Enabled = false
	svc, closer, _, _, err := buildService(cfg, discardLogger(), nil, nil) // CLI is one-shot: no metrics, no receipts
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer closer()
	var opts []cli.Option
	if failInvalid {
		opts = append(opts, cli.FailOnInvalid())
	}
	return cli.Run(core.ContextWithLocale(context.Background(), cfg.Locale), svc, op, os.Stdin, os.Stdout, opts...)
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
	signer, err := loadServiceKey(cfg, log)
	if err != nil {
		log.Error("startup failed", "error", err)
		return 1
	}
	svc, closer, refresher, report, err := buildService(cfg, log, rec, signer)
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

	oidcProv, err := buildOIDC(cfg, svc, signer, log)
	if err != nil {
		log.Error("oidc subsystem setup failed", "error", err)
		return 1
	}
	if oidcProv != nil {
		rec.BindOIDC(oidcProv.ActiveChallenges)
	}

	var watcher *certwatch.Watcher
	if cfg.CertWatch.Enabled {
		watcher = certwatch.New(svc, certwatch.Config{
			Dir:             cfg.CertWatch.Dir,
			Interval:        cfg.CertWatch.ResolveInterval(),
			WarnFrom:        cfg.CertWatch.ResolveWarnFrom(),
			WebhookURL:      cfg.CertWatch.WebhookURL,
			CheckRevocation: cfg.CertWatch.CheckRevocation,
			Log:             log,
		})
		rec.BindCertWatch(func() []metrics.CertWatchState {
			states := watcher.States()
			out := make([]metrics.CertWatchState, 0, len(states))
			for _, st := range states {
				out = append(out, metrics.CertWatchState{
					File: st.File, Subject: st.Subject, ExpiresIn: st.ExpiresIn,
					HasExpiry: st.NotAfter != nil, Revoked: st.Revoked, Failed: st.Error != "",
				})
			}
			return out
		})
	}

	challengeSvc, err := buildChallenge(cfg, svc)
	if err != nil {
		log.Error("challenge subsystem setup failed", "error", err)
		return 1
	}
	if challengeSvc != nil {
		rec.BindChallenges(challengeSvc.Active)
	}

	multisignSvc, err := buildMultisign(cfg, svc)
	if err != nil {
		log.Error("multisign subsystem setup failed", "error", err)
		return 1
	}
	if multisignSvc != nil {
		rec.BindMultisign(multisignSvc.Active)
	}

	qrOrch, err := buildQR(cfg, svc, oidcProv, log)
	if err != nil {
		log.Error("qr subsystem setup failed", "error", err)
		return 1
	}
	if qrOrch != nil {
		rec.BindQR(qrOrch.ActiveSessions)
	}

	return serve(cfg, svc, subsystems{
		jobs: mgr, oidc: oidcProv, qr: qrOrch, challenge: challengeSvc,
		signer: signer, refresher: refresher, certwatch: watcher, multisign: multisignSvc,
	}, rec, ready, status, log)
}

// loadServiceKey loads the one RS256 key the service signs its own statements
// with — OIDC tokens and verification receipts alike. One key means one JWKS and
// one identity for consumers to trust. It returns nil when nothing needs it.
func loadServiceKey(cfg config.Config, log *slog.Logger) (*oidc.Signer, error) {
	if !cfg.OIDC.Enabled && !cfg.Receipts.Enabled {
		return nil, nil
	}
	signer, err := oidc.LoadOrGenerate(cfg.OIDC.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("service signing key: %w", err)
	}
	if signer.Ephemeral && log != nil {
		log.Warn("service signing key is ephemeral: set oidc.key-path to persist it (the JWKS kid rotates on restart, invalidating live tokens and past receipts)")
	}
	return signer, nil
}

// buildOIDC constructs the OIDC "login with ЭЦП" provider when enabled: the
// service token signer, a challenge store, and the flow over the domain service.
// It returns a nil provider (no error) when OIDC is disabled.
func buildOIDC(cfg config.Config, svc *core.Service, signer *oidc.Signer, log *slog.Logger) (*oidc.Provider, error) {
	if !cfg.OIDC.Enabled {
		return nil, nil
	}
	if signer == nil {
		return nil, fmt.Errorf("oidc enabled without a service signing key")
	}
	// Trust anchors are the auth boundary: OIDC verifies with a cert-time check that
	// forces the signer chain to validate to a trusted NUC root, so a cert that does
	// not chain to a configured anchor cannot grant a login. Without anchors that
	// check fails for every certificate — OIDC would be unusable and, more to the
	// point, unsafe. Warn loudly.
	if !cfg.Trust.UseRKRegistry && cfg.Trust.CADir == "" {
		log.Warn("oidc enabled without trust anchors: set trust.use-rk-registry or trust.ca-dir so the signer chain validates to a NUC root (login rejects otherwise)")
	}
	var store oidc.ChallengeStore
	switch cfg.OIDC.Store {
	case "bolt":
		bs, err := oidc.OpenBoltStore(cfg.OIDC.BoltPath)
		if err != nil {
			return nil, fmt.Errorf("open oidc challenge store: %w", err)
		}
		store = bs
	default:
		store = oidc.NewMemStore()
	}
	clients, err := oidc.ParseClients(cfg.OIDC.Clients)
	if err != nil {
		return nil, fmt.Errorf("oidc clients: %w", err)
	}
	if len(clients) == 0 {
		log.Info("oidc: no clients registered — the browser redirect flow is off, the API grant still works")
	}
	prov := oidc.New(svc, signer, store, oidc.Config{
		Issuer:       cfg.OIDC.Issuer,
		Audience:     cfg.OIDC.Audience,
		ChallengeTTL: cfg.OIDC.OIDCChallengeTTL(),
		TokenTTL:     cfg.OIDC.OIDCTokenTTL(),
		RequireOCSP:  cfg.OIDC.RequireOCSP,
	}, oidc.WithLogger(log), oidc.WithClients(clients))
	return prov, nil
}

// buildChallenge constructs the standalone challenge-response service when
// enabled. It returns a nil service (no error) when the feature is off.
func buildChallenge(cfg config.Config, svc *core.Service) (*challenge.Service, error) {
	if !cfg.Challenge.Enabled {
		return nil, nil
	}
	var store challenge.Store
	switch cfg.Challenge.Store {
	case "bolt":
		bs, err := challenge.OpenBoltStore(cfg.Challenge.BoltPath)
		if err != nil {
			return nil, fmt.Errorf("open challenge store: %w", err)
		}
		store = bs
	default:
		store = challenge.NewMemStore()
	}
	return challenge.New(svc, store, challenge.Config{
		TTL:         cfg.Challenge.ChallengeTTL(),
		RequireOCSP: cfg.Challenge.RequireOCSP,
	}), nil
}

// buildMultisign constructs the multi-signature session service when enabled.
func buildMultisign(cfg config.Config, svc *core.Service) (*multisign.Service, error) {
	if !cfg.Multisign.Enabled {
		return nil, nil
	}
	var store multisign.Store
	switch cfg.Multisign.Store {
	case "bolt":
		bs, err := multisign.OpenBoltStore(cfg.Multisign.BoltPath)
		if err != nil {
			return nil, fmt.Errorf("open multisign store: %w", err)
		}
		store = bs
	default:
		store = multisign.NewMemStore()
	}
	return multisign.New(svc, store, multisign.Config{TTL: cfg.Multisign.ResolveTTL()}), nil
}

// buildQR constructs the eGov Mobile QR orchestrator when enabled: a session store,
// the enabled profiles (agnostic + egov always; relay when a gateway URL is set)
// and, for auth-mode sessions, the OIDC provider as the shared token issuer. It
// returns a nil orchestrator (no error) when QR is disabled.
func buildQR(cfg config.Config, svc *core.Service, oidcProv *oidc.Provider, log *slog.Logger) (*qr.Orchestrator, error) {
	if !cfg.QR.Enabled {
		return nil, nil
	}
	var store qr.SessionStore
	switch cfg.QR.Store {
	case "bolt":
		bs, err := qr.OpenBoltStore(cfg.QR.BoltPath)
		if err != nil {
			return nil, fmt.Errorf("open qr session store: %w", err)
		}
		store = bs
	default:
		store = qr.NewMemStore()
	}
	profiles := map[qr.Profile]qr.Profiler{
		qr.ProfileAgnostic: qr.NewAgnosticProfile(),
		qr.ProfileEGov:     qr.NewEGovProfile(qr.EGovConfig{Organization: cfg.QR.Organization}),
	}
	if cfg.QR.RelayURL != "" {
		profiles[qr.ProfileRelay] = qr.NewRelayProfile(qr.RelayConfig{BaseURL: cfg.QR.RelayURL, OrgID: cfg.QR.RelayID})
	}
	// The QR flow verifies the returned signature — the same trust-anchor boundary
	// as OIDC applies (the chain must validate to a NUC root), so warn if none.
	if !cfg.Trust.UseRKRegistry && cfg.Trust.CADir == "" {
		log.Warn("qr enabled without trust anchors: set trust.use-rk-registry or trust.ca-dir so the signer chain validates (verification rejects otherwise)")
	}
	opts := []qr.Option{qr.WithLogger(log), qr.WithWebhook(qrWebhook(log))}
	if oidcProv != nil {
		opts = append(opts, qr.WithTokenIssuer(oidcProv))
	}
	orch := qr.New(svc, store, profiles, qr.Config{
		DefaultProfile: qr.Profile(cfg.QR.DefaultProfile),
		DefaultMode:    qr.Mode(cfg.QR.DefaultMode),
		TTL:            cfg.QR.QRSessionTTL(),
		RequireOCSP:    cfg.QR.RequireOCSP,
	}, opts...)
	return orch, nil
}

// qrWebhook delivers a terminal QR-session notification by POSTing the client-safe
// view to the consumer's callbackUrl. Best-effort: a failure is logged, not
// retried. The view carries no secrets or signature bytes beyond the result.
func qrWebhook(log *slog.Logger) qr.Webhook {
	return func(ctx context.Context, url string, v qr.View) {
		body, err := json.Marshal(v)
		if err != nil {
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			log.Warn("qr webhook build failed", "session", v.ID, "error", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Warn("qr webhook delivery failed", "session", v.ID, "error", err)
			return
		}
		_ = resp.Body.Close()
	}
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
// subsystems groups the optional pieces serve wires into the transports. They
// are gathered in one value because they share a lifecycle (started with the
// serve context, closed on shutdown) and because passing them one by one had
// outgrown a readable signature.
type subsystems struct {
	jobs      *jobs.Manager
	oidc      *oidc.Provider
	qr        *qr.Orchestrator
	challenge *challenge.Service
	certwatch *certwatch.Watcher
	multisign *multisign.Service
	signer    *oidc.Signer // service signing key: OIDC tokens and receipts
	refresher *trust.Refresher
}

func serve(cfg config.Config, svc *core.Service, sub subsystems, rec *metrics.Recorder, ready func() bool, status func() rest.StatusInfo, log *slog.Logger) int {
	mgr, oidcProv, qrOrch, refresher := sub.jobs, sub.oidc, sub.qr, sub.refresher
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The async-job manager shares the serve context: its pool drains when ctx is
	// canceled. It is served over REST and gRPC, so warn only if neither is on.
	if mgr != nil {
		if !cfg.HTTP.Enabled && !cfg.GRPC.Enabled {
			log.Warn("jobs enabled but neither REST nor gRPC is on: job endpoints will not be reachable")
		}
		if err := mgr.Start(ctx); err != nil {
			log.Error("job manager start failed", "error", err)
			return 1
		}
	}

	// The OIDC provider is served over REST only. Its challenge reaper drains with
	// ctx.
	if oidcProv != nil {
		if !cfg.HTTP.Enabled {
			log.Warn("oidc enabled but REST is off: the /oidc endpoints will not be reachable")
		}
		oidcProv.Start(ctx)
	}

	// The certificate watcher runs regardless of transport: its output is metrics
	// and webhooks, not an endpoint.
	if sub.certwatch != nil {
		sub.certwatch.Start(ctx)
	}

	// Standalone challenges are served over REST only. The reaper drains with ctx.
	if sub.challenge != nil {
		if !cfg.HTTP.Enabled {
			log.Warn("challenge enabled but REST is off: the /challenge endpoints will not be reachable")
		}
		sub.challenge.Start(ctx)
	}

	// The QR orchestrator is served over REST only. Its session reaper drains with ctx.
	if qrOrch != nil {
		if !cfg.HTTP.Enabled {
			log.Warn("qr enabled but REST is off: the /qr endpoints will not be reachable")
		}
		qrOrch.Start(ctx)
	}

	// Background trust-anchor refresh drains with ctx. A resolved interval of 0
	// (default without the RK registry, or an explicit 0/off) makes Run a no-op.
	if interval := cfg.TrustRefreshInterval(); interval > 0 {
		log.Info("trust auto-refresh enabled", "interval", interval.String())
		go refresher.Run(ctx, interval)
	}

	// Shared idempotency cache: one instance backs both the REST Idempotency-Key
	// header and the MQ envelope idempotencyKey so a retry/redelivery replays the
	// first result across transports. Nil (disabled) is a transparent passthrough.
	var idemCache *idempotency.Cache
	if cfg.Idempotency.Enabled {
		idemCache = idempotency.New(cfg.Idempotency.ResolveTTL(), cfg.Idempotency.ResolveMaxEntries(), nil)
		log.Info("idempotency enabled", "ttl", cfg.Idempotency.ResolveTTL().String(), "maxEntries", cfg.Idempotency.ResolveMaxEntries())
	}

	obs := rest.Observability(ready, status)
	var shutdowns []func(context.Context)

	if cfg.HTTP.Enabled {
		var restOpts []rest.Option
		if mgr != nil {
			restOpts = append(restOpts, rest.WithJobs(mgr))
		}
		if idemCache != nil {
			restOpts = append(restOpts, rest.WithIdempotency(idemCache))
		}
		if oidcProv != nil {
			restOpts = append(restOpts, rest.WithOIDC(oidcProv))
		}
		if sub.signer != nil {
			restOpts = append(restOpts, rest.WithServiceKey(sub.signer))
		}
		if sub.challenge != nil {
			restOpts = append(restOpts, rest.WithChallenge(sub.challenge))
		}
		if sub.multisign != nil {
			restOpts = append(restOpts, rest.WithMultisign(sub.multisign))
		}
		if cfg.Portal.Enabled {
			restOpts = append(restOpts, rest.WithPortal())
		}
		if cfg.Receipts.SignedQR && sub.signer != nil {
			restOpts = append(restOpts, rest.WithSignedQR(
				signedqr.New(sub.signer, sub.signer, cfg.ReceiptIssuer())))
		}
		if cfg.Console.Enabled {
			restOpts = append(restOpts, rest.WithConsole())
		}
		if cfg.Console.SandboxKey != "" {
			log.Warn("sandbox signing is enabled: anyone who can reach /sandbox/sign can sign arbitrary data with that key",
				"key", cfg.Console.SandboxKey)
			restOpts = append(restOpts, rest.WithSandboxKey(cfg.Console.SandboxKey, cfg.Console.SandboxKeyPassword))
		}
		if cfg.Audit.Enabled && cfg.Audit.Expose {
			restOpts = append(restOpts, rest.WithAudit(cfg.Audit.Path, auditEntryVerifier(sub.signer)))
		}
		if qrOrch != nil {
			restOpts = append(restOpts, rest.WithQR(qrOrch, cfg.QR.PublicBaseURL))
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
		var grpcOpts []grpctransport.Option
		if mgr != nil {
			grpcOpts = append(grpcOpts, grpctransport.WithJobs(mgr))
		}
		// Interceptor order: metrics, then the service default language, then the
		// per-call override from accept-language metadata.
		gs := grpclib.NewServer(grpclib.ChainUnaryInterceptor(
			rec.UnaryInterceptor(),
			localeUnaryInterceptor(cfg.Locale),
			grpctransport.LocaleInterceptor(),
			// Replays a repeated idempotency-key instead of re-executing, matching
			// the REST header. A nil cache makes it a pass-through.
			grpctransport.IdempotencyInterceptor(idemCache),
		))
		grpctransport.New(svc, grpcOpts...).Register(gs)
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
		var procOpts []mq.Option
		if mgr != nil {
			procOpts = append(procOpts, mq.WithJobs(mgr))
		}
		if idemCache != nil {
			procOpts = append(procOpts, mq.WithIdempotency(idemCache))
		}
		startMQ(ctx, &mqWG, cfg, mq.NewProcessor(svc, rec, procOpts...), log, stop)
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
	if oidcProv != nil {
		if err := oidcProv.Close(); err != nil {
			log.Warn("oidc store close", "error", err)
		}
	}
	if sub.multisign != nil {
		if err := sub.multisign.Close(); err != nil {
			log.Warn("multisign store close", "error", err)
		}
	}
	if sub.challenge != nil {
		if err := sub.challenge.Close(); err != nil {
			log.Warn("challenge store close", "error", err)
		}
	}
	if qrOrch != nil {
		if err := qrOrch.Close(); err != nil {
			log.Warn("qr store close", "error", err)
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

// runCryptoWorker is the child side of the out-of-process driver. It is not a
// user-facing command: the service spawns it and speaks a private protocol over
// stdin/stdout, so nothing but that protocol may be written there.
//
// It takes the library flags directly instead of loading the full configuration:
// the child runs crypto operations and nothing else, so transports, job stores
// and listen addresses have no business in its process.
func runCryptoWorker(args []string) int {
	fs := flag.NewFlagSet("crypto-worker", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	libPath := fs.String("lib-path", "", "path to libkalkancryptwr-64.so (BYOL)")
	libVersion := fs.String("lib-version", "", "override library version detection")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	pool, err := native.Open(native.Config{WrapperPath: *libPath, PoolSize: 1, Version: *libVersion})
	if err != nil {
		fmt.Fprintf(os.Stderr, "crypto-worker: %v\n", err)
		return 1
	}
	defer func() { _ = pool.Close() }()
	if err := cryptoworker.Serve(context.Background(), os.Stdin, os.Stdout, pool); err != nil {
		fmt.Fprintf(os.Stderr, "crypto-worker: %v\n", err)
		return 1
	}
	return 0
}

// startCryptoWorker brings up the child processes that run the crypto
// operations, re-executing this binary in its crypto-worker mode. The child
// inherits the environment so the loader settings the library needs (library
// search paths, preloads) reach it unchanged.
func startCryptoWorker(cfg config.Config, log *slog.Logger) (*cryptoworker.Supervisor, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate own binary: %w", err)
	}
	command := []string{exe, "crypto-worker", "-lib-path=" + cfg.Lib.Path}
	if cfg.Lib.Version != "" {
		command = append(command, "-lib-version="+cfg.Lib.Version)
	}
	return cryptoworker.Start(cryptoworker.Config{
		Command:          command,
		Size:             cfg.CryptoWorker.ResolveProcesses(cfg.Workers),
		CallTimeout:      cfg.CryptoWorker.ResolveTimeout(),
		MaxOps:           cfg.CryptoWorker.MaxOps,
		MaxRSSBytes:      cfg.CryptoWorker.ResolveMaxRSSBytes(),
		Standby:          cfg.CryptoWorker.Standby,
		KeepAfterRevoked: cfg.CryptoWorker.KeepAfterRevoked,
		Log:              log,
	})
}

// openDriver brings up the crypto driver the service will use and assesses BYOL
// compatibility. By default the driver runs in child processes: the library leaks
// native memory on every operation and corrupts its global state on a revoked
// OCSP verdict, and neither can be undone inside a process — so the service keeps
// no library of its own and the children are recycled. With the worker disabled
// the pool is opened in-process, as before.
func openDriver(cfg config.Config, log *slog.Logger) (cryptoworker.Driver, compat.Report, error) {
	if !cfg.CryptoWorker.Enabled {
		return openLibrary(cfg)
	}
	sup, err := startCryptoWorker(cfg, log)
	if err != nil {
		return nil, compat.Report{}, fmt.Errorf("start crypto worker: %w", err)
	}
	self, err := sup.SelfTest(context.Background())
	if err != nil {
		_ = sup.Close()
		return nil, compat.Report{}, fmt.Errorf("self-test: %w", err)
	}
	report := compat.Evaluate(cfg.Lib.Path, sup.Capabilities(), self, compat.Requirements{
		MinVersion:  cfg.Lib.MinVersion,
		RequireSign: !cfg.VerifyOnly,
	})
	return sup, report, nil
}

// buildService opens the driver pool, enforces the compatibility policy, and
// assembles the domain service with its infrastructure (key source, trust
// store). It refuses to build the service when the library is incompatible under
// the configured policy (a self-test failure always refuses).
func buildService(cfg config.Config, log *slog.Logger, rec *metrics.Recorder, signer *oidc.Signer) (*core.Service, func(), *trust.Refresher, compat.Report, error) {
	prov, report, err := openDriver(cfg, log)
	if err != nil {
		return nil, nil, nil, compat.Report{}, err
	}
	bindDriverMetrics(rec, prov)
	policy, _ := compat.ParsePolicy(cfg.Lib.Compat) // validated by config.Validate
	if log != nil {
		logReport(log, report, policy)
	}
	if report.MustRefuse(policy) {
		_ = prov.Close()
		return nil, nil, nil, report, fmt.Errorf("library incompatible (policy=%s), refusing to start:\n%s",
			policy, report.Text())
	}

	store, err := trust.LoadDir(cfg.Trust.CADir)
	if err != nil {
		_ = prov.Close()
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
		cache := crl.New(crl.Config{
			Timeout:  time.Duration(cfg.Trust.AIATimeout) * time.Second,
			SpoolDir: cfg.Trust.CRLSpoolDir,
			MaxBytes: int64(cfg.Trust.CRLCacheMaxMB) << 20,
		})
		rec.BindCRL(cache.Stats)
		opts = append(opts, core.WithCRLSource(cache))
		if cfg.Trust.CRLFailPolicy == "hard" {
			opts = append(opts, core.WithCRLFailPolicy(core.CRLFailHard))
		}
	}
	if cfg.Trust.OCSPCache {
		oc := ocspcache.New(ocspcache.Config{
			TTL:        cfg.Trust.ResolveOCSPCacheTTL(),
			MaxEntries: cfg.Trust.OCSPCacheMaxEntries,
		})
		rec.BindOCSPCache(oc.Stats)
		opts = append(opts, core.WithOCSPCache(ocspcache.Port(oc)))
	}
	if cfg.Trust.VerifyChain {
		opts = append(opts, core.WithChainVerification(true))
	}
	// A typed nil would satisfy the port interface and panic on use, so the signer
	// is only wired when it actually exists.
	if cfg.Receipts.Enabled && signer != nil {
		opts = append(opts, core.WithReceiptSigner(signer, cfg.ReceiptIssuer()))
	}
	var journal *audit.Log
	if cfg.Audit.Enabled {
		var aerr error
		// The journal is signed with the same service key when there is one; without
		// it the chain still detects edits, just not a re-seal.
		journal, aerr = audit.Open(audit.Config{Path: cfg.Audit.Path, Sync: cfg.Audit.Sync}, auditSigner(signer))
		if aerr != nil {
			_ = prov.Close()
			return nil, nil, nil, report, fmt.Errorf("open audit journal: %w", aerr)
		}
		opts = append(opts, core.WithAudit(audit.NewSink(journal, log)))
	}
	if cfg.Input.Enabled() {
		opts = append(opts, core.WithDataResolver(dataref.New(dataref.Config{
			AllowLocalPath: cfg.Input.AllowLocalPath,
			AllowURL:       cfg.Input.AllowURL,
			AllowedSchemes: cfg.Input.AllowedSchemes,
			MaxBytes:       int64(cfg.Input.MaxMB) << 20,
			SpoolDir:       cfg.Input.SpoolDir,
		})))
	}
	svc := core.New(prov, opts...)
	closer := func() {
		if journal != nil {
			if err := journal.Close(); err != nil && log != nil {
				log.Warn("audit journal close", "error", err)
			}
		}
		if err := prov.Close(); err != nil && log != nil {
			log.Warn("driver close", "error", err)
		}
	}
	return svc, closer, refresher, report, nil
}

// auditSigner returns the service key as the journal's signer, or nil when there
// is none — a typed nil would satisfy the interface and panic on first use.
func auditSigner(signer *oidc.Signer) audit.Signer {
	if signer == nil {
		return nil
	}
	return signer
}

// bindDriverMetrics wires whichever driver is in use to the metric registry: the
// pool utilization gauge in both shapes, plus the child-process lifecycle
// counters when the worker holds the library.
func bindDriverMetrics(rec *metrics.Recorder, driver cryptoworker.Driver) {
	switch d := driver.(type) {
	case *cryptoworker.Supervisor:
		rec.BindPool(d.PoolStats)
		rec.BindCryptoWorker(func() (spawns, crashes, recycles, timeouts, hotSwaps uint64) {
			st := d.WorkerStats()
			return st.Spawns, st.Crashes, st.Recycles, st.Timeouts, st.HotSwaps
		})
	case *native.Pool:
		rec.BindPool(d.Stats)
	}
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

// localeUnaryInterceptor seeds every gRPC call with the service's default
// language, which the per-call metadata interceptor may then override.
func localeUnaryInterceptor(defaultLocale string) grpclib.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpclib.UnaryServerInfo, handler grpclib.UnaryHandler) (any, error) {
		return handler(core.ContextWithLocale(ctx, defaultLocale), req)
	}
}

// auditEntryVerifier checks a journal entry's signature against the service key.
// Without a key it returns nil: the chain is still verified, which catches edits
// but not a chain re-sealed by whoever holds the key.
func auditEntryVerifier(signer *oidc.Signer) func(audit.Entry) error {
	if signer == nil {
		return nil
	}
	return func(e audit.Entry) error {
		claims, err := signer.Verify(e.Signature, time.Now())
		if err != nil {
			return err
		}
		if hash, _ := claims["hash"].(string); hash != e.Hash {
			return fmt.Errorf("signature covers a different entry")
		}
		return nil
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
