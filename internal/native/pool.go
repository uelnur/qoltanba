package native

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"os"
	"sync"
	"sync/atomic"

	"github.com/uelnur/qoltanba/internal/provider"
)

// Pool is the concurrency-safe implementation of provider.Provider. It holds N
// isolated Kalkan instances, each pinned to its own worker on its own OS thread.
// Requests go into a shared queue; a free worker takes the next one, giving
// natural load balancing: up to N operations run in parallel, but each instance
// runs strictly sequentially. Callers never serialize anything.
type Pool struct {
	jobs    chan job
	quit    chan struct{}
	wg      sync.WaitGroup
	closed  atomic.Bool
	once    sync.Once
	caps    provider.Capabilities
	cleanup []string     // temp files (the patched wrapper) to remove on Close
	inUse   atomic.Int64 // jobs currently dispatched to a worker (for metrics)
}

var _ provider.Provider = (*Pool)(nil)

// newPool starts workers over ready instances. It is separate from Open so tests
// can inject fake instances without the native library.
func newPool(instances []kalkanInstance, caps provider.Capabilities) *Pool {
	p := &Pool{
		jobs: make(chan job), // unbuffered: a send succeeds only when a worker is ready
		quit: make(chan struct{}),
		caps: caps,
	}
	p.caps.PoolSize = len(instances)
	for i := range instances {
		w := &worker{inst: instances[i], jobs: p.jobs, quit: p.quit}
		p.wg.Add(1)
		started := make(chan struct{})
		go func() {
			defer p.wg.Done()
			w.run(started)
		}()
		<-started // wait for LockOSThread so Close cannot race the startup
	}
	return p
}

// submit enqueues a job and waits for its result. The context guards only the
// enqueue (backpressure): while the job is not yet picked up, cancellation
// returns ctx.Err(). Once dispatched we wait unconditionally — a native call
// cannot be interrupted, and the job writes the caller's memory (captured
// variables), so reading it before done would race. If the context was canceled
// while the job ran, we report it, but the work has completed.
func (p *Pool) submit(ctx context.Context, fn func(inst kalkanInstance) error) error {
	if p.closed.Load() {
		return provider.ErrClosed
	}
	j := job{fn: fn, done: make(chan error, 1)}
	select {
	case p.jobs <- j: // picked up by a worker (the channel is unbuffered)
		p.inUse.Add(1)
		defer p.inUse.Add(-1)
	case <-p.quit:
		return provider.ErrClosed
	case <-ctx.Done():
		return ctx.Err() // job never started — captured variables untouched
	}
	err := <-j.done
	if err == nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Close stops the workers and releases every instance. It is idempotent.
func (p *Pool) Close() error {
	p.once.Do(func() {
		p.closed.Store(true)
		close(p.quit)
		p.wg.Wait()
		removeAll(p.cleanup)
	})
	return nil
}

// Capabilities returns the capability map of the loaded library version.
func (p *Pool) Capabilities() provider.Capabilities { return p.caps }

// Stats reports pool utilization for metrics: jobs currently running on a worker
// and the total worker count.
func (p *Pool) Stats() (inUse, size int) {
	return int(p.inUse.Load()), p.caps.PoolSize
}

func (p *Pool) SignCMS(ctx context.Context, req provider.SignRequest) (provider.SignResult, error) {
	if !p.caps.SignCMS {
		return provider.SignResult{}, provider.ErrUnsupported
	}
	var out []byte
	err := p.submit(ctx, func(inst kalkanInstance) error {
		alias, err := inst.loadKey(req.Key)
		if err != nil {
			return err
		}
		// With CheckCertTime the library anchors the signer's chain, so the CA(s)
		// must be in the store before signing (leaf-only otherwise fails 0x08F00042).
		if err := loadTrusted(inst, req.TrustedCerts); err != nil {
			return err
		}
		if req.WithTimestamp {
			inst.tsaSetURL(req.TSAURL)
		}
		// With KC_IN_FILE the library reads the content from a path; the "data" arg
		// then carries the path bytes and Data is unused (nothing buffered here).
		data := req.Data
		if req.Path != "" {
			data = []byte(req.Path)
		}
		sig, err := inst.signData(alias, signCMSFlags(req), data, req.ExistingSignature)
		if err != nil {
			return err
		}
		out = sig
		return nil
	})
	return provider.SignResult{Signature: out}, err
}

func (p *Pool) VerifyCMS(ctx context.Context, req provider.VerifyRequest) (provider.VerifyResult, error) {
	if !p.caps.VerifyCMS {
		return provider.VerifyResult{}, provider.ErrUnsupported
	}
	var res provider.VerifyResult
	err := p.submit(ctx, func(inst kalkanInstance) error {
		flags := verifyCMSFlags(req) // must match the signing flags
		data := req.Data
		if req.Path != "" {
			data = []byte(req.Path) // KC_IN_FILE: detached source read from a path
		}
		vo := inst.verifyData("", flags, data, req.Signature, req.SignerIndex)
		res.RawCode = vo.code
		res.Valid = vo.code == kcrOK
		res.Info = string(vo.verify)
		res.Content = vo.data
		res.SignerCert = vo.cert
		// All signers (multi-signature): walk 1-based sigId via KC_GetCertFromCMS
		// until no more certificates come back.
		certFlags := kcOutPEM
		if req.InputPEM {
			certFlags |= kcInPEM
		}
		for sigID := 1; sigID <= 64; sigID++ {
			cert, crc := inst.certFromCMS(req.Signature, sigID, certFlags)
			if crc != kcrOK || len(cert) == 0 {
				break
			}
			res.Signers = append(res.Signers, cert)
		}
		// If VerifyData returned no signer certificate, take it from the walk.
		if len(res.SignerCert) == 0 && len(res.Signers) > 0 {
			idx := req.SignerIndex
			if idx < 0 || idx >= len(res.Signers) {
				idx = 0
			}
			res.SignerCert = res.Signers[idx]
		}
		inFlag := 0
		if req.InputPEM {
			inFlag = kcInPEM
		}
		if t, rc := inst.timeFromSig(req.Signature, inFlag, 0); rc == kcrOK {
			res.Timestamp = t
		}
		if vo.code != kcrOK {
			return nativeErr("VerifyCMS", vo.code, "")
		}
		return nil
	})
	return res, err
}

func (p *Pool) SignXML(ctx context.Context, req provider.SignXMLRequest) (provider.SignResult, error) {
	if !p.caps.SignXML {
		return provider.SignResult{}, provider.ErrUnsupported
	}
	var out []byte
	err := p.submit(ctx, func(inst kalkanInstance) error {
		alias, err := inst.loadKey(req.Key)
		if err != nil {
			return err
		}
		if err := loadTrusted(inst, req.TrustedCerts); err != nil {
			return err
		}
		if req.WithTimestamp {
			inst.tsaSetURL(req.TSAURL)
		}
		flags := 0
		if !req.CheckCertTime {
			flags |= kcNoCheckCertTime
		}
		if req.WithTimestamp {
			flags |= kcWithTimestamp
		}
		sig, err := inst.signXML(alias, flags, req.XML, req.NodeID, req.ParentNode, req.ParentNS)
		if err != nil {
			return err
		}
		out = sig
		return nil
	})
	return provider.SignResult{Signature: out}, err
}

func (p *Pool) VerifyXML(ctx context.Context, req provider.VerifyRequest) (provider.VerifyResult, error) {
	if !p.caps.VerifyXML {
		return provider.VerifyResult{}, provider.ErrUnsupported
	}
	var res provider.VerifyResult
	err := p.submit(ctx, func(inst kalkanInstance) error {
		if err := loadTrusted(inst, req.TrustedCerts); err != nil {
			return err
		}
		flags := 0
		if !req.CheckCertTime {
			flags |= kcNoCheckCertTime
		}
		info, rc := inst.verifyXML("", flags, req.Signature)
		res.RawCode = rc
		res.Valid = rc == kcrOK
		res.Info = string(info)
		// All signers (multi-signature): walk 1-based sigId via KC_getCertFromXML
		// until no more certificates come back — same shape as VerifyCMS.
		for sigID := 1; sigID <= 64; sigID++ {
			cert, crc := inst.certFromXML(req.Signature, sigID)
			if crc != kcrOK || len(cert) == 0 {
				break
			}
			res.Signers = append(res.Signers, cert)
		}
		if len(res.Signers) > 0 {
			idx := req.SignerIndex
			if idx < 0 || idx >= len(res.Signers) {
				idx = 0
			}
			res.SignerCert = res.Signers[idx]
		}
		if rc != kcrOK {
			return nativeErr("VerifyXML", rc, "")
		}
		return nil
	})
	return res, err
}

func (p *Pool) SignWSSE(ctx context.Context, req provider.SignWSSERequest) (provider.SignResult, error) {
	if !p.caps.WSSE {
		return provider.SignResult{}, provider.ErrUnsupported
	}
	var out []byte
	err := p.submit(ctx, func(inst kalkanInstance) error {
		alias, err := inst.loadKey(req.Key)
		if err != nil {
			return err
		}
		if err := loadTrusted(inst, req.TrustedCerts); err != nil {
			return err
		}
		if req.WithTimestamp {
			inst.tsaSetURL(req.TSAURL)
		}
		flags := 0
		if !req.CheckCertTime {
			flags |= kcNoCheckCertTime
		}
		if req.WithTimestamp {
			flags |= kcWithTimestamp
		}
		sig, err := inst.signWSSE(alias, flags, req.XML, req.NodeID)
		if err != nil {
			return err
		}
		out = sig
		return nil
	})
	return provider.SignResult{Signature: out}, err
}

func (p *Pool) ExportOwnerCert(ctx context.Context, key provider.KeyRef, format provider.CertFormat) (provider.ExportResult, error) {
	if !p.caps.ExportCert {
		return provider.ExportResult{}, provider.ErrUnsupported
	}
	var res provider.ExportResult
	err := p.submit(ctx, func(inst kalkanInstance) error {
		alias, err := inst.loadKey(key)
		if err != nil {
			return err
		}
		res.Alias = alias
		// X509ExportCertificateFromStore ignores the DER/B64 format flag and
		// always returns PEM (verified against v2.0.13). Request PEM — the format
		// it reliably produces (text, NUL-safe) — and convert in Go.
		raw, err := inst.exportCert(alias, kcCertPEM)
		if err != nil {
			return err
		}
		cert, err := certToFormat(raw, format)
		if err != nil {
			return err
		}
		res.Cert = cert
		return nil
	})
	return res, err
}

// certToFormat converts an exported certificate (PEM from the library, or DER as
// a fallback) into the requested encoding. DER is exact bytes; B64 is base64 of
// the DER; PEM is the standard armored form.
func certToFormat(raw []byte, format provider.CertFormat) ([]byte, error) {
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		der = block.Bytes
	}
	switch format {
	case provider.CertDER:
		return der, nil
	case provider.CertB64:
		return []byte(base64.StdEncoding.EncodeToString(der)), nil
	default: // CertPEM
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
	}
}

func (p *Pool) Hash(ctx context.Context, req provider.HashRequest) (provider.HashResult, error) {
	if !p.caps.Hash {
		return provider.HashResult{}, provider.ErrUnsupported
	}
	var h []byte
	err := p.submit(ctx, func(inst kalkanInstance) error {
		// On v2.0.13 HashData selects the algorithm by FLAG (KC_HASH_*), not by
		// the string; the string is kept for OID-capable builds.
		out, err := inst.hashData(req.Algorithm, hashFlags(req.Algorithm), req.Data)
		if err != nil {
			return err
		}
		h = out
		return nil
	})
	return provider.HashResult{Hash: h}, err
}

func (p *Pool) SignHash(ctx context.Context, req provider.SignHashRequest) (provider.SignResult, error) {
	if !p.caps.Hash {
		return provider.SignResult{}, provider.ErrUnsupported
	}
	var out []byte
	err := p.submit(ctx, func(inst kalkanInstance) error {
		alias, err := inst.loadKey(req.Key)
		if err != nil {
			return err
		}
		flags := 0
		if req.OutPEM {
			flags |= kcOutPEM
		}
		if !req.CheckCertTime {
			flags |= kcNoCheckCertTime
		}
		sig, err := inst.signHash(alias, flags, req.Hash)
		if err != nil {
			return err
		}
		out = sig
		return nil
	})
	return provider.SignResult{Signature: out}, err
}

func (p *Pool) CertProperties(ctx context.Context, cert []byte, _ provider.CertFormat) (provider.CertProperties, error) {
	if !p.caps.CertInfo {
		return provider.CertProperties{}, provider.ErrUnsupported
	}
	var props provider.CertProperties
	err := p.submit(ctx, func(inst kalkanInstance) error {
		props = inst.certInfo(cert)
		return nil
	})
	return props, err
}

func (p *Pool) ValidateCert(ctx context.Context, req provider.ValidateRequest) (provider.ValidateResult, error) {
	if !p.caps.Validate {
		return provider.ValidateResult{}, provider.ErrUnsupported
	}
	var res provider.ValidateResult
	err := p.submit(ctx, func(inst kalkanInstance) error {
		if err := loadTrusted(inst, req.TrustedCerts); err != nil {
			return err
		}
		validType := kcUseOCSP
		switch req.Method {
		case provider.ValidateCRL:
			validType = kcUseCRL
		case provider.ValidateNone:
			validType = kcUseNothing
		}
		vo := inst.validate(req.Cert, validType, req.Path, req.CheckTime.Unix(), req.WantOCSP)
		res.RawCode = vo.code
		res.Info = string(vo.info)
		res.OCSPResponse = vo.ocsp
		res.Status = mapCertStatus(vo.code)
		if res.Status == provider.StatusUnknown && vo.code != kcrOK && vo.code != kcrCertStatusUnknown {
			return nativeErr("ValidateCert", vo.code, string(vo.info))
		}
		return nil
	})
	return res, err
}

// loadTrusted loads a set of trusted CAs into an instance's trust store.
func loadTrusted(inst kalkanInstance, cas []provider.TrustedCert) error {
	for _, ca := range cas {
		certType := kcCertCA
		if ca.Intermediate {
			certType = kcCertIntermediate
		}
		if err := loadTrustedFromBytes(inst, ca.Cert, certType); err != nil {
			return err
		}
	}
	return nil
}

// loadTrustedFromBytes writes a CA to a temp file and loads it into the
// instance's trust store, since the C-API has no load-from-buffer variant.
func loadTrustedFromBytes(inst kalkanInstance, cert []byte, certType int) error {
	f, err := os.CreateTemp("", "kalkan-ca-*.cer")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(cert); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return inst.loadCertFile(name, certType)
}

func signCMSFlags(req provider.SignRequest) int {
	flags := kcSignCMS
	if req.InputPEM {
		flags |= kcInPEM
	}
	if req.OutPEM {
		flags |= kcOutPEM
	}
	if req.Detached {
		flags |= kcDetachedData
	}
	if !req.CheckCertTime {
		flags |= kcNoCheckCertTime
	}
	if req.WithTimestamp {
		flags |= kcWithTimestamp
	}
	if req.Path != "" {
		flags |= kcInFile // the library reads the content from the path
	}
	return flags
}

func verifyCMSFlags(req provider.VerifyRequest) int {
	flags := kcSignCMS
	if req.InputPEM {
		flags |= kcInPEM
	}
	if req.OutPEM {
		flags |= kcOutPEM
	}
	if req.Detached {
		flags |= kcDetachedData
	}
	if !req.CheckCertTime {
		flags |= kcNoCheckCertTime
	}
	if req.Path != "" {
		flags |= kcInFile
	}
	return flags
}

// hashFlags maps an algorithm name to a native KC_HASH_* flag (HashData selects
// the algorithm by flag). An unknown name yields 0 (select by string/OID).
func hashFlags(alg string) int {
	switch alg {
	case "SHA256", "sha256", "2.16.840.1.101.3.4.2.1":
		return kcHashSHA256
	case "GOST95", "GOST34311", "1.2.398.3.10.1.1.1":
		return kcHashGOST95
	default:
		return 0
	}
}

// mapCertStatus interprets a validation code. Over OCSP the library returns
// 0 (good) / 1 (revoked) — these are NOT KCR_CERT_STATUS_* codes, so read both.
func mapCertStatus(code uint32) provider.CertStatus {
	switch code {
	case kcrOK, kcrCertStatusOK:
		return provider.StatusGood
	case 1, kcrCertStatusRevoked:
		return provider.StatusRevoked
	default:
		return provider.StatusUnknown
	}
}
