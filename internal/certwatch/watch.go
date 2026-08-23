// Package certwatch keeps an eye on certificates a consumer cares about —
// service keys, long-lived signer certificates — and reports when one is revoked
// or about to expire.
//
// The service already answers "is this certificate valid right now" on request.
// What an operator cannot get that way is advance warning: nobody asks about a
// service key until a signature fails at 3am. A watcher polls the same checks on
// a schedule and turns the answer into a metric and, optionally, a webhook, so
// the failure is anticipated rather than discovered.
package certwatch

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// Defaults for an unset Config field.
const (
	defaultInterval = 6 * time.Hour
	defaultWarnFrom = 30 * 24 * time.Hour
	webhookTimeout  = 10 * time.Second
)

// Validator is the slice of the domain a watcher needs: parse a certificate and
// check its revocation status.
type Validator interface {
	CertInfo(ctx context.Context, in core.CertInfoInput) (core.CertInfoOutput, error)
	Validate(ctx context.Context, in core.ValidateInput) (core.ValidateOutput, error)
}

// Config parameterizes a Watcher.
type Config struct {
	// Dir holds the watched certificates (PEM or DER, one certificate per file).
	Dir string
	// Interval is how often each certificate is re-checked. Zero uses 6h: a
	// revocation is not an emergency to detect within seconds, and each check
	// costs an OCSP request.
	Interval time.Duration
	// WarnFrom is how far ahead an upcoming expiry starts being reported. Zero
	// uses 30 days — enough time to reissue an ЭЦП without rushing.
	WarnFrom time.Duration
	// WebhookURL receives an event when a certificate becomes revoked or enters
	// the expiry window. Empty disables webhooks (the metrics still update).
	WebhookURL string
	// CheckRevocation reaches the OCSP responder. Disable it to watch expiry only,
	// e.g. in an environment with no outbound access.
	CheckRevocation bool
	Log             *slog.Logger
	Now             func() time.Time
	HTTP            *http.Client
}

// State is what the watcher knows about one certificate.
type State struct {
	File         string     `json:"file"`
	Subject      string     `json:"subject"`
	SerialNumber string     `json:"serialNumber,omitempty"`
	NotAfter     *time.Time `json:"notAfter,omitempty"`
	Revoked      bool       `json:"revoked"`
	// ExpiresIn is time left until NotAfter; negative once expired.
	ExpiresIn time.Duration `json:"-"`
	CheckedAt time.Time     `json:"checkedAt"`
	// Error records why the last check could not complete. A watcher that cannot
	// check must not silently report "fine".
	Error string `json:"error,omitempty"`
}

// Event is what a webhook receives.
type Event struct {
	Kind  string `json:"kind"` // revoked | expiring | expired | check_failed
	State State  `json:"certificate"`
}

// Watcher polls the watched certificates.
type Watcher struct {
	validator Validator
	cfg       Config

	mu     sync.RWMutex
	states map[string]State
	// notified remembers which event kind was last sent per certificate, so a
	// webhook fires on a change of situation rather than on every poll.
	notified map[string]string
}

// New builds a watcher over the domain service.
func New(v Validator, cfg Config) *Watcher {
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.WarnFrom <= 0 {
		cfg.WarnFrom = defaultWarnFrom
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: webhookTimeout}
	}
	return &Watcher{
		validator: v,
		cfg:       cfg,
		states:    make(map[string]State),
		notified:  make(map[string]string),
	}
}

// Start runs the polling loop until ctx ends. The first sweep runs immediately:
// an operator who just enabled the watcher should see its metrics without waiting
// for a full interval.
func (w *Watcher) Start(ctx context.Context) {
	go func() {
		w.Sweep(ctx)
		t := time.NewTicker(w.cfg.Interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				w.Sweep(ctx)
			}
		}
	}()
}

// Sweep checks every watched certificate once.
func (w *Watcher) Sweep(ctx context.Context) {
	files, err := certFiles(w.cfg.Dir)
	if err != nil {
		w.cfg.Log.Warn("certwatch: cannot read the watch directory", "dir", w.cfg.Dir, "error", err)
		return
	}
	for _, file := range files {
		state := w.check(ctx, file)
		w.mu.Lock()
		w.states[file] = state
		w.mu.Unlock()
		w.notify(ctx, state)
	}
}

// check inspects one certificate file.
func (w *Watcher) check(ctx context.Context, file string) State {
	now := w.cfg.Now()
	state := State{File: filepath.Base(file), CheckedAt: now}

	raw, err := os.ReadFile(file)
	if err != nil {
		state.Error = err.Error()
		return state
	}
	der, format := decodeCert(raw)
	if der == nil {
		state.Error = "not a certificate (PEM or DER expected)"
		return state
	}
	// Parsing locally covers subject and validity without a native call; only the
	// revocation check needs the driver.
	if cert, perr := x509.ParseCertificate(der); perr == nil {
		state.Subject = cert.Subject.CommonName
		if state.Subject == "" {
			state.Subject = cert.Subject.String()
		}
		state.SerialNumber = fmt.Sprintf("%X", cert.SerialNumber)
		notAfter := cert.NotAfter.UTC()
		state.NotAfter = &notAfter
		state.ExpiresIn = notAfter.Sub(now)
	} else {
		state.Error = "parse: " + perr.Error()
		return state
	}

	if !w.cfg.CheckRevocation {
		return state
	}
	out, err := w.validator.Validate(ctx, core.ValidateInput{
		Cert: raw, Format: format, Method: core.MethodOCSP,
	})
	switch {
	case err != nil:
		state.Error = "revocation: " + err.Error()
	case out.Status.LibError != nil && !out.Status.Revoked:
		// An inconclusive answer is recorded as such: reporting "not revoked"
		// because the responder was unreachable is exactly the wrong answer.
		state.Error = "revocation inconclusive: " + out.Status.LibError.Message
	default:
		state.Revoked = out.Status.Revoked
	}
	return state
}

// notify emits a webhook when a certificate's situation changes. The event kind
// is the situation, so a certificate does not re-notify on every sweep while
// nothing moves.
func (w *Watcher) notify(ctx context.Context, s State) {
	kind := eventKind(s, w.cfg.WarnFrom)

	w.mu.Lock()
	previous := w.notified[s.File]
	if kind == previous {
		w.mu.Unlock()
		return
	}
	w.notified[s.File] = kind
	w.mu.Unlock()

	if kind == "" {
		return // back to healthy: nothing to raise
	}
	w.cfg.Log.Warn("certwatch: certificate needs attention",
		"kind", kind, "subject", s.Subject, "file", s.File, "notAfter", s.NotAfter, "error", s.Error)
	if w.cfg.WebhookURL == "" {
		return
	}
	if err := w.postEvent(ctx, Event{Kind: kind, State: s}); err != nil {
		// A failed webhook must not hide the finding: the log and the metric
		// already carry it, so this is a delivery problem, not a check problem.
		w.cfg.Log.Warn("certwatch: webhook delivery failed", "error", err)
		w.mu.Lock()
		delete(w.notified, s.File) // retry on the next sweep
		w.mu.Unlock()
	}
}

func (w *Watcher) postEvent(ctx context.Context, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

// eventKind classifies a state, or "" when nothing needs attention.
func eventKind(s State, warnFrom time.Duration) string {
	switch {
	case s.Error != "":
		return "check_failed"
	case s.Revoked:
		return "revoked"
	case s.NotAfter != nil && s.ExpiresIn <= 0:
		return "expired"
	case s.NotAfter != nil && s.ExpiresIn <= warnFrom:
		return "expiring"
	default:
		return ""
	}
}

// States returns the current view, sorted by file for stable output.
func (w *Watcher) States() []State {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]State, 0, len(w.states))
	for _, s := range w.states {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out
}

// certFiles lists candidate certificate files in dir.
func certFiles(dir string) ([]string, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".cer", ".crt", ".pem", ".der":
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

// decodeCert accepts PEM or DER and reports which it was, so the revocation call
// passes the bytes through in the encoding the driver expects.
func decodeCert(raw []byte) ([]byte, core.CertEncoding) {
	if block, _ := pem.Decode(raw); block != nil && block.Type == "CERTIFICATE" {
		return block.Bytes, core.EncodingPEM
	}
	if _, err := x509.ParseCertificate(raw); err == nil {
		return raw, core.EncodingDER
	}
	return nil, ""
}
