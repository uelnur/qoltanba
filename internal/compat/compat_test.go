package compat

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/uelnur/qoltanba/internal/provider"
)

// fullCaps is a capability map with everything present, at a good version.
func fullCaps(version string) provider.Capabilities {
	return provider.Capabilities{
		Version: version, PoolSize: 1,
		SignCMS: true, VerifyCMS: true, SignXML: true, VerifyXML: true,
		CertInfo: true, Validate: true, Timestamp: true, ZipSign: true,
		WSSE: true, Hash: true, ExportCert: true,
	}
}

func passSelfTest() provider.SelfTestResult {
	return provider.SelfTestResult{Ran: true, OK: true, Algorithm: "SHA256", Detail: "match"}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"2.0.13", "2.0.0", 1, true},
		{"2.0.0", "2.0.13", -1, true},
		{"2.0.0", "2.0.0", 0, true},
		{"2.0", "2.0.0", 0, true},  // missing segment == zero
		{"2.1", "2.0.13", 1, true}, // 2.1 > 2.0.x
		{"3", "2.9.9", 1, true},    // major dominates
		{"unknown", "2.0.0", 0, false},
		{"", "2.0.0", 0, false},
		{"2.0.x", "2.0.0", 0, false}, // non-numeric segment
	}
	for _, c := range cases {
		got, ok := compareVersions(c.a, c.b)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("compareVersions(%q,%q) = (%d,%v), want (%d,%v)", c.a, c.b, got, ok, c.want, c.ok)
		}
	}
}

func TestParsePolicy(t *testing.T) {
	for in, want := range map[string]Policy{
		"strict": PolicyStrict, "STRICT": PolicyStrict, "": PolicyStrict,
		"warn": PolicyWarn, "off": PolicyOff,
	} {
		got, err := ParsePolicy(in)
		if err != nil || got != want {
			t.Errorf("ParsePolicy(%q) = (%v,%v), want %v", in, got, err, want)
		}
	}
	if _, err := ParsePolicy("bogus"); err == nil {
		t.Error("ParsePolicy(bogus) should error")
	}
}

func TestEvaluateCompatible(t *testing.T) {
	r := Evaluate("/lib.so", fullCaps("2.0.13"), passSelfTest(), Requirements{MinVersion: "2.0.0", RequireSign: true})
	if v := r.VerdictString(); v != "compatible" {
		t.Fatalf("verdict = %q, want compatible; report:\n%s", v, r.Text())
	}
	if !r.Compatible() || r.MustRefuse(PolicyStrict) {
		t.Error("a fully compatible library must not refuse under any policy")
	}
}

func TestEvaluateVersionBelowMinimum(t *testing.T) {
	r := Evaluate("/lib.so", fullCaps("1.9.9"), passSelfTest(), Requirements{MinVersion: "2.0.0", RequireSign: true})
	if r.Verdict() != StatusFail {
		t.Fatalf("verdict = %v, want FAIL", r.Verdict())
	}
	// Non-critical failure: strict refuses, warn/off proceed.
	if !r.MustRefuse(PolicyStrict) {
		t.Error("strict policy must refuse a below-minimum version")
	}
	if r.MustRefuse(PolicyWarn) || r.MustRefuse(PolicyOff) {
		t.Error("warn/off must not refuse on a version shortfall")
	}
}

func TestEvaluateUnknownVersionWarns(t *testing.T) {
	r := Evaluate("/lib.so", fullCaps("unknown"), passSelfTest(), Requirements{MinVersion: "2.0.0", RequireSign: true})
	if r.Verdict() != StatusWarn {
		t.Fatalf("verdict = %v, want WARN (unknown version is not a hard fail)", r.Verdict())
	}
	if r.MustRefuse(PolicyStrict) {
		t.Error("an unknown version is a warning, not a refusal, even under strict")
	}
}

func TestSelfTestMismatchAlwaysRefuses(t *testing.T) {
	self := provider.SelfTestResult{Ran: true, OK: false, Algorithm: "SHA256", Detail: "mismatch"}
	r := Evaluate("/lib.so", fullCaps("2.0.13"), self, Requirements{MinVersion: "2.0.0", RequireSign: true})
	if r.Verdict() != StatusFail {
		t.Fatalf("verdict = %v, want FAIL", r.Verdict())
	}
	// A miscomputing library is unusable: every policy must refuse.
	for _, p := range []Policy{PolicyStrict, PolicyWarn, PolicyOff} {
		if !r.MustRefuse(p) {
			t.Errorf("self-test failure must refuse under policy %s", p)
		}
	}
}

func TestSelfTestSkippedWarns(t *testing.T) {
	self := provider.SelfTestResult{Ran: false, Algorithm: "SHA256", Detail: "HashData unavailable"}
	r := Evaluate("/lib.so", fullCaps("2.0.13"), self, Requirements{MinVersion: "2.0.0", RequireSign: true})
	if r.Verdict() != StatusWarn {
		t.Fatalf("verdict = %v, want WARN for a skipped self-test", r.Verdict())
	}
	if r.MustRefuse(PolicyStrict) {
		t.Error("a skipped (not failed) self-test must not refuse")
	}
}

func TestMissingRequiredCapabilityFails(t *testing.T) {
	caps := fullCaps("2.0.13")
	caps.VerifyCMS = false // required everywhere
	r := Evaluate("/lib.so", caps, passSelfTest(), Requirements{MinVersion: "2.0.0", RequireSign: true})
	if r.Verdict() != StatusFail {
		t.Fatalf("verdict = %v, want FAIL when a required capability is missing", r.Verdict())
	}
	if !r.MustRefuse(PolicyStrict) || r.MustRefuse(PolicyWarn) {
		t.Error("missing required capability: strict refuses, warn proceeds")
	}
}

func TestSignRequiredOnlyOutsideVerifyOnly(t *testing.T) {
	caps := fullCaps("2.0.13")
	caps.SignCMS = false
	// verify-only: SignCMS is not required → still compatible.
	r := Evaluate("/lib.so", caps, passSelfTest(), Requirements{MinVersion: "2.0.0", RequireSign: false})
	if !r.Compatible() {
		t.Errorf("verify-only must not require SignCMS; report:\n%s", r.Text())
	}
	// full mode: SignCMS required → fails.
	r = Evaluate("/lib.so", caps, passSelfTest(), Requirements{MinVersion: "2.0.0", RequireSign: true})
	if r.Compatible() {
		t.Error("full mode must require SignCMS")
	}
}

func TestMissingOptionalCapabilityWarns(t *testing.T) {
	caps := fullCaps("2.0.13")
	caps.ZipSign = false
	r := Evaluate("/lib.so", caps, passSelfTest(), Requirements{MinVersion: "2.0.0", RequireSign: true})
	if r.Verdict() != StatusWarn {
		t.Fatalf("verdict = %v, want WARN (degraded) for a missing optional capability", r.Verdict())
	}
	if !r.Compatible() {
		t.Error("a degraded library is still compatible (usable)")
	}
}

func TestNoMinimumEnforced(t *testing.T) {
	r := Evaluate("/lib.so", fullCaps("unknown"), passSelfTest(), Requirements{MinVersion: "", RequireSign: true})
	for _, c := range r.Checks {
		if c.Name == "version" && c.Status != StatusPass {
			t.Errorf("empty MinVersion should pass the version check, got %v", c.Status)
		}
	}
}

func TestTextAndJSON(t *testing.T) {
	r := Evaluate("/native/libkalkancryptwr-64.so.2.0.13", fullCaps("2.0.13"), passSelfTest(),
		Requirements{MinVersion: "2.0.0", RequireSign: true})

	txt := r.Text()
	for _, want := range []string{"compatibility report", "2.0.13", "Verdict: COMPATIBLE", "self-test"} {
		if !strings.Contains(txt, want) {
			t.Errorf("Text() missing %q\n%s", want, txt)
		}
	}

	b, err := r.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var parsed struct {
		Verdict      string          `json:"verdict"`
		Compatible   bool            `json:"compatible"`
		Capabilities map[string]bool `json:"capabilities"`
		SelfTest     struct {
			OK bool `json:"ok"`
		} `json:"selfTest"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Verdict != "compatible" || !parsed.Compatible || !parsed.SelfTest.OK {
		t.Errorf("unexpected JSON projection: %+v", parsed)
	}
	if !parsed.Capabilities["SignCMS"] {
		t.Error("capabilities map should report SignCMS present")
	}
}
