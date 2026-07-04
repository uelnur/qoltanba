// Package compat evaluates whether a consumer-supplied (BYOL) Kalkan library is
// compatible with the service before it starts serving. It is pure, cgo-free
// logic over the driver's already-collected facts (version, capability map,
// smoke self-test), so it is unit-tested with synthetic inputs and no native
// library. The driver gathers the facts; this package judges them and renders a
// detailed report.
package compat

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/uelnur/qoltanba/internal/provider"
)

// Policy decides what an incompatible library does to startup. A self-test
// failure (the library computes incorrectly) always blocks regardless of
// policy; the policy only governs version/capability shortfalls.
type Policy int

const (
	PolicyStrict Policy = iota // refuse to start on any failing check
	PolicyWarn                 // log prominently and start anyway
	PolicyOff                  // report only, never gate
)

// ParsePolicy maps a config string to a Policy.
func ParsePolicy(s string) (Policy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "strict", "":
		return PolicyStrict, nil
	case "warn":
		return PolicyWarn, nil
	case "off":
		return PolicyOff, nil
	default:
		return PolicyStrict, fmt.Errorf("unknown compatibility policy %q (want strict|warn|off)", s)
	}
}

func (p Policy) String() string {
	switch p {
	case PolicyWarn:
		return "warn"
	case PolicyOff:
		return "off"
	default:
		return "strict"
	}
}

// Status is a single check's outcome; higher is worse.
type Status int

const (
	StatusPass Status = iota
	StatusWarn
	StatusFail
)

func (s Status) String() string {
	switch s {
	case StatusWarn:
		return "WARN"
	case StatusFail:
		return "FAIL"
	default:
		return "PASS"
	}
}

// Check is one evaluated aspect of compatibility.
type Check struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
	// Critical marks a failure that blocks startup regardless of policy (a
	// library that computes incorrectly is unusable). Only the self-test sets it.
	Critical bool `json:"critical,omitempty"`
}

// Requirements are the thresholds the library is judged against.
type Requirements struct {
	// MinVersion is the lowest supported library version (e.g. "2.0.0"). Empty
	// disables the version floor.
	MinVersion string
	// RequireSign demands the signing capabilities too (false in verify-only
	// mode, where only verification and cert inspection are needed).
	RequireSign bool
}

// Report is the full compatibility assessment.
type Report struct {
	LibPath  string
	Version  string
	PoolSize int
	Isolated bool
	Caps     provider.Capabilities
	SelfTest provider.SelfTestResult
	Checks   []Check
}

// Evaluate judges the collected facts against the requirements and returns a
// detailed report.
func Evaluate(libPath string, caps provider.Capabilities, self provider.SelfTestResult, req Requirements) Report {
	r := Report{
		LibPath:  libPath,
		Version:  caps.Version,
		PoolSize: caps.PoolSize,
		Isolated: caps.PoolSize > 1,
		Caps:     caps,
		SelfTest: self,
	}
	r.Checks = append(r.Checks,
		loadCheck(caps),
		versionCheck(caps.Version, req.MinVersion),
		selfTestCheck(self),
	)
	r.Checks = append(r.Checks, capabilityChecks(caps, req.RequireSign)...)
	return r
}

func loadCheck(caps provider.Capabilities) Check {
	return Check{
		Name:   "load",
		Status: StatusPass,
		Detail: fmt.Sprintf("library loaded and initialized (pool of %d, isolated=%v)", caps.PoolSize, caps.PoolSize > 1),
	}
}

func versionCheck(version, min string) Check {
	c := Check{Name: "version"}
	if min == "" {
		c.Status = StatusPass
		c.Detail = fmt.Sprintf("detected version %s (no minimum enforced)", displayVersion(version))
		return c
	}
	cmp, ok := compareVersions(version, min)
	switch {
	case !ok:
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("version could not be determined (%s); cannot confirm it is >= %s", displayVersion(version), min)
	case cmp < 0:
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("version %s is below the minimum supported %s", version, min)
	default:
		c.Status = StatusPass
		c.Detail = fmt.Sprintf("version %s satisfies the minimum %s", version, min)
	}
	return c
}

func selfTestCheck(self provider.SelfTestResult) Check {
	c := Check{Name: "self-test"}
	switch {
	case self.Ran && self.OK:
		c.Status = StatusPass
		c.Detail = self.Detail
	case self.Ran && !self.OK:
		// The library ran the digest and got the wrong answer: it is unusable.
		c.Status = StatusFail
		c.Critical = true
		c.Detail = "self-test FAILED — " + self.Detail
	default:
		// Could not run (digest primitive absent): correctness unproven, but not
		// proven broken, so warn rather than fail.
		c.Status = StatusWarn
		c.Detail = "self-test skipped — " + self.Detail
	}
	return c
}

// capEntry pairs a capability name with its presence.
type capEntry struct {
	name    string
	present bool
}

func capabilityChecks(caps provider.Capabilities, requireSign bool) []Check {
	// Required: the service's reason to exist is verification and certificate
	// inspection; signing is required only outside verify-only mode.
	required := []capEntry{
		{"VerifyCMS", caps.VerifyCMS},
		{"CertInfo", caps.CertInfo},
		{"Validate", caps.Validate},
	}
	if requireSign {
		required = append(required, capEntry{"SignCMS", caps.SignCMS})
	}
	optional := []capEntry{
		{"SignXML", caps.SignXML},
		{"VerifyXML", caps.VerifyXML},
		{"WSSE", caps.WSSE},
		{"Timestamp", caps.Timestamp},
		{"ZipSign", caps.ZipSign},
		{"Hash", caps.Hash},
		{"ExportCert", caps.ExportCert},
	}

	var checks []Check

	reqMissing := missing(required)
	req := Check{Name: "required-capabilities"}
	if len(reqMissing) > 0 {
		req.Status = StatusFail
		req.Detail = "missing required capabilities: " + strings.Join(reqMissing, ", ")
	} else {
		req.Status = StatusPass
		req.Detail = "all required capabilities present: " + strings.Join(names(required), ", ")
	}
	checks = append(checks, req)

	optMissing := missing(optional)
	opt := Check{Name: "optional-capabilities"}
	if len(optMissing) > 0 {
		opt.Status = StatusWarn
		opt.Detail = "unavailable in this library version: " + strings.Join(optMissing, ", ")
	} else {
		opt.Status = StatusPass
		opt.Detail = "all optional capabilities present"
	}
	checks = append(checks, opt)

	return checks
}

func missing(entries []capEntry) []string {
	var out []string
	for _, e := range entries {
		if !e.present {
			out = append(out, e.name)
		}
	}
	return out
}

func names(entries []capEntry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.name
	}
	return out
}

// Verdict is the worst status across all checks.
func (r Report) Verdict() Status {
	worst := StatusPass
	for _, c := range r.Checks {
		if c.Status > worst {
			worst = c.Status
		}
	}
	return worst
}

// VerdictString renders the overall verdict as a word.
func (r Report) VerdictString() string {
	switch r.Verdict() {
	case StatusFail:
		return "incompatible"
	case StatusWarn:
		return "degraded"
	default:
		return "compatible"
	}
}

// Compatible reports whether nothing failed (warnings are still usable).
func (r Report) Compatible() bool { return r.Verdict() != StatusFail }

// MustRefuse reports whether startup must be refused under the given policy. A
// critical failure (self-test) always refuses; a non-critical failure refuses
// only under strict policy.
func (r Report) MustRefuse(p Policy) bool {
	anyFail := false
	for _, c := range r.Checks {
		if c.Status != StatusFail {
			continue
		}
		if c.Critical {
			return true
		}
		anyFail = true
	}
	return anyFail && p == PolicyStrict
}

// Text renders a human-readable report.
func (r Report) Text() string {
	var b strings.Builder
	b.WriteString("Kalkan library compatibility report\n")
	fmt.Fprintf(&b, "  library path : %s\n", orNA(r.LibPath))
	fmt.Fprintf(&b, "  version      : %s\n", displayVersion(r.Version))
	fmt.Fprintf(&b, "  pool size    : %d (isolated: %v)\n", r.PoolSize, r.Isolated)
	b.WriteString("\nChecks:\n")
	for _, c := range r.Checks {
		crit := ""
		if c.Critical && c.Status == StatusFail {
			crit = " (critical)"
		}
		fmt.Fprintf(&b, "  [%s] %-22s %s%s\n", c.Status, c.Name, c.Detail, crit)
	}
	b.WriteString("\nCapabilities:\n")
	for _, e := range capabilityList(r.Caps) {
		mark := "no"
		if e.present {
			mark = "yes"
		}
		fmt.Fprintf(&b, "  %-12s %s\n", e.name, mark)
	}
	fmt.Fprintf(&b, "\nVerdict: %s\n", strings.ToUpper(r.VerdictString()))
	return b.String()
}

// jsonReport is the machine-readable projection of a Report.
type jsonReport struct {
	LibPath      string          `json:"libPath"`
	Version      string          `json:"version"`
	PoolSize     int             `json:"poolSize"`
	Isolated     bool            `json:"isolated"`
	Verdict      string          `json:"verdict"`
	Compatible   bool            `json:"compatible"`
	SelfTest     selfTestJSON    `json:"selfTest"`
	Checks       []checkJSON     `json:"checks"`
	Capabilities map[string]bool `json:"capabilities"`
}

type selfTestJSON struct {
	Ran       bool   `json:"ran"`
	OK        bool   `json:"ok"`
	Algorithm string `json:"algorithm"`
	Detail    string `json:"detail"`
}

type checkJSON struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Detail   string `json:"detail"`
	Critical bool   `json:"critical,omitempty"`
}

// JSON renders the report as indented JSON.
func (r Report) JSON() ([]byte, error) {
	jr := jsonReport{
		LibPath:    r.LibPath,
		Version:    r.Version,
		PoolSize:   r.PoolSize,
		Isolated:   r.Isolated,
		Verdict:    r.VerdictString(),
		Compatible: r.Compatible(),
		SelfTest: selfTestJSON{
			Ran: r.SelfTest.Ran, OK: r.SelfTest.OK,
			Algorithm: r.SelfTest.Algorithm, Detail: r.SelfTest.Detail,
		},
		Capabilities: map[string]bool{},
	}
	for _, c := range r.Checks {
		jr.Checks = append(jr.Checks, checkJSON{
			Name: c.Name, Status: c.Status.String(), Detail: c.Detail, Critical: c.Critical,
		})
	}
	for _, e := range capabilityList(r.Caps) {
		jr.Capabilities[e.name] = e.present
	}
	return json.MarshalIndent(jr, "", "  ")
}

// capabilityList flattens the capability map to a stable ordered slice.
func capabilityList(c provider.Capabilities) []capEntry {
	return []capEntry{
		{"SignCMS", c.SignCMS},
		{"VerifyCMS", c.VerifyCMS},
		{"SignXML", c.SignXML},
		{"VerifyXML", c.VerifyXML},
		{"CertInfo", c.CertInfo},
		{"Validate", c.Validate},
		{"Timestamp", c.Timestamp},
		{"ZipSign", c.ZipSign},
		{"WSSE", c.WSSE},
		{"Hash", c.Hash},
		{"ExportCert", c.ExportCert},
	}
}

// compareVersions compares dotted numeric versions (e.g. "2.0.13" vs "2.0.0").
// It returns -1/0/1 and whether both were parseable. Missing trailing segments
// are treated as zero, so "2.0" == "2.0.0".
func compareVersions(a, b string) (int, bool) {
	as, aok := parseVersion(a)
	bs, bok := parseVersion(b)
	if !aok || !bok {
		return 0, false
	}
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av != bv {
			if av < bv {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

// parseVersion splits a dotted numeric version into its segments. It fails on an
// empty string, "unknown", or any non-numeric segment.
func parseVersion(v string) ([]int, bool) {
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "unknown") {
		return nil, false
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func displayVersion(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

func orNA(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}
