package config

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, args ...string) *Loaded {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	l, err := Load(fs, args)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return l
}

func TestPrecedence_DefaultEnvFlag(t *testing.T) {
	// Default.
	if l := load(t); l.Config.Log.Level != "info" {
		t.Errorf("default log.level = %q, want info", l.Config.Log.Level)
	}

	// Env overrides default.
	t.Setenv("QOLTANBA_LOG_LEVEL", "warn")
	if l := load(t); l.Config.Log.Level != "warn" || l.origins["log.level"] != "env" {
		t.Errorf("env log.level = %q (%s), want warn (env)", l.Config.Log.Level, l.origins["log.level"])
	}

	// Flag overrides env.
	l := load(t, "-log-level", "debug")
	if l.Config.Log.Level != "debug" || l.origins["log.level"] != "flag" {
		t.Errorf("flag log.level = %q (%s), want debug (flag)", l.Config.Log.Level, l.origins["log.level"])
	}
}

func TestFileLayer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(path, []byte("log:\n  level: error\nworkers: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := load(t, "-config", path)
	if l.Config.Log.Level != "error" || l.origins["log.level"] != "file" {
		t.Errorf("file log.level = %q (%s), want error (file)", l.Config.Log.Level, l.origins["log.level"])
	}
	if l.Config.Workers != 3 {
		t.Errorf("file workers = %d, want 3", l.Config.Workers)
	}
	// A key absent from the file keeps its default origin.
	if l.origins["http.addr"] != "default" {
		t.Errorf("http.addr origin = %q, want default", l.origins["http.addr"])
	}

	// Env still beats the file.
	t.Setenv("QOLTANBA_WORKERS", "5")
	if l := load(t, "-config", path); l.Config.Workers != 5 {
		t.Errorf("env over file workers = %d, want 5", l.Config.Workers)
	}
}

func TestSecretFileConvention(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "level")
	if err := os.WriteFile(secret, []byte("debug\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// <VAR>_FILE sources the value from a side-file (used for secrets/mounts).
	t.Setenv("QOLTANBA_LOG_LEVEL_FILE", secret)
	l := load(t)
	if l.Config.Log.Level != "debug" {
		t.Errorf("_FILE log.level = %q, want debug", l.Config.Log.Level)
	}
}

func TestValidate(t *testing.T) {
	// Missing lib.path is reported.
	l := load(t)
	if err := l.Validate(); err == nil || !strings.Contains(err.Error(), "lib.path") {
		t.Errorf("expected lib.path error, got %v", err)
	}
	// workers>1 without isolation is rejected.
	l = load(t, "-lib-path", "/x.so", "-workers", "4")
	if err := l.Validate(); err == nil || !strings.Contains(err.Error(), "isolated") {
		t.Errorf("expected isolation error, got %v", err)
	}
	// Valid config passes.
	l = load(t, "-lib-path", "/x.so")
	if err := l.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDumpRedactsAndShowsOrigin(t *testing.T) {
	t.Setenv("QOLTANBA_LOG_LEVEL", "warn")
	out := load(t).Dump()
	if !strings.Contains(out, "log.level") || !strings.Contains(out, "(env)") {
		t.Errorf("dump missing origin: %s", out)
	}
}
