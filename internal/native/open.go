package native

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Config holds driver load parameters. BYOL: the consumer supplies the native
// library paths (they are not in the repository).
type Config struct {
	// WrapperPath is the path to libkalkancryptwr-64.so (required).
	WrapperPath string
	// PoolSize is the number of instances = the max parallel operations. <1
	// becomes 1. Values >1 require Isolated with working isolation, otherwise
	// instances share crypto-engine state and crash the process under load.
	PoolSize int
	// Isolated loads each instance into a private link namespace (dlmopen),
	// realizing "each worker its own Kalkan". Requires Linux, patchelf and a
	// correct IsolationDeps.
	Isolated bool
	// IsolationDeps are the wrapper dependencies baked into its DT_NEEDED in
	// isolated mode (iconv shim, libkalkancrypto, libm, libpcsclite): a private
	// namespace ignores LD_PRELOAD, and dlmopen rejects RTLD_GLOBAL, so symbols
	// can only enter via NEEDED. Use absolute paths.
	IsolationDeps []string
	// Version overrides version detection (otherwise it is derived from the file
	// name).
	Version string
}

// Open loads PoolSize Kalkan instances and returns a concurrency-safe Provider.
// On any error the already-opened instances are released.
func Open(cfg Config) (*Pool, error) {
	if cfg.WrapperPath == "" {
		return nil, fmt.Errorf("kalkan: WrapperPath not set (BYOL: path to libkalkancryptwr-64.so)")
	}
	size := cfg.PoolSize
	if size < 1 {
		size = 1
	}
	if size > 1 && !cfg.Isolated {
		return nil, fmt.Errorf("kalkan: PoolSize>1 requires Isolated=true (else instances share crypto-engine state)")
	}

	// Isolation only matters for a pool >1 (a single instance shares nothing).
	isolate := cfg.Isolated && size > 1

	// In isolated mode prepare one wrapper with dependencies in DT_NEEDED, shared
	// across all instances: dlmopen(LM_ID_NEWLM) from it yields independent
	// namespaces.
	wrapperPath := cfg.WrapperPath
	var cleanup []string
	if isolate {
		pw, err := prepareNamespaceWrapper(cfg.WrapperPath, cfg.IsolationDeps)
		if err != nil {
			return nil, fmt.Errorf("kalkan: prepare isolated wrapper: %w", err)
		}
		wrapperPath = pw
		cleanup = append(cleanup, pw)
	}

	insts := make([]kalkanInstance, 0, size)
	fail := func(err error) (*Pool, error) {
		closeAll(insts)
		removeAll(cleanup)
		return nil, err
	}
	for i := 0; i < size; i++ {
		in, err := openInstance(i, wrapperPath, isolate)
		if err != nil {
			return fail(err)
		}
		// A multi-instance pool is safe only with real isolation. If dlmopen fell
		// back to a shared dlopen, state is shared, so refuse — concurrent work
		// would crash the process (verified empirically).
		if isolate && !in.isIsolated() {
			in.close()
			return fail(fmt.Errorf("kalkan: instance %d isolation not achieved "+
				"(dlmopen namespace did not assemble); PoolSize>1 is unsafe — "+
				"check IsolationDeps/platform or set PoolSize=1", i))
		}
		insts = append(insts, in)
	}

	caps := detectCaps(insts[0], cfg)
	p := newPool(insts, caps)
	p.cleanup = cleanup
	return p, nil
}

// prepareNamespaceWrapper copies the wrapper and bakes dependencies into its
// DT_NEEDED with patchelf. dlmopen rejects RTLD_GLOBAL and a fresh namespace
// does not see LD_PRELOAD, so the only way to bring iconv/crypto/… symbols in is
// to declare them as the wrapper's own dependencies. Then each namespace pulls
// its own copy of libkalkancrypto, isolating crypto-engine state. Needs patchelf.
func prepareNamespaceWrapper(src string, deps []string) (string, error) {
	real, err := filepath.EvalSymlinks(src)
	if err != nil {
		real = src
	}
	data, err := os.ReadFile(real)
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp("", "kkwr-ns-*.so")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	// Absolute paths in DT_NEEDED: the loader takes them directly, no rpath search.
	args := []string{}
	for _, d := range deps {
		args = append(args, "--add-needed", d)
	}
	args = append(args, name)
	if out, err := exec.Command("patchelf", args...).CombinedOutput(); err != nil {
		os.Remove(name)
		return "", fmt.Errorf("patchelf (required for isolation): %w: %s", err, out)
	}
	return name, nil
}

func closeAll(insts []kalkanInstance) {
	for _, in := range insts {
		in.close()
	}
}

func removeAll(paths []string) {
	for _, p := range paths {
		os.Remove(p)
	}
}

// Isolated reports whether the pool runs with real per-instance isolation.
func (p *Pool) Isolated() bool { return p.caps.PoolSize > 1 }
