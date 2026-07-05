package qr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RelayConfig points the relay profile at an upstream eGov QR gateway (e.g. SIGEX).
// We are a client of that gateway: it hosts the URLs eGov Mobile actually hits, so
// this profile works without registering our own service on Smart Bridge.
type RelayConfig struct {
	BaseURL string       // gateway base, e.g. "https://sigex.kz"
	OrgID   string       // optional path segment: /api/{OrgID}/egovQr
	Client  *http.Client // injectable for tests; defaults to a 15s client
}

// relayProfile drives the basic three-call gateway flow: register → upload
// documents → poll for signatures.
type relayProfile struct {
	cfg    RelayConfig
	client *http.Client
}

// NewRelayProfile builds the upstream-gateway (relay) profile.
func NewRelayProfile(cfg RelayConfig) Profiler { return newRelayProfile(cfg) }

func newRelayProfile(cfg RelayConfig) relayProfile {
	c := cfg.Client
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return relayProfile{cfg: cfg, client: c}
}

func (relayProfile) SelfHosted() bool { return false }

// registerResp is the gateway's register/upload response (superset).
type registerResp struct {
	ExpireAt               int64  `json:"expireAt"`
	QRCode                 string `json:"qrCode"`
	EGovMobileLaunchLink   string `json:"eGovMobileLaunchLink"`
	EGovBusinessLaunchLink string `json:"eGovBusinessLaunchLink"`
	DataURL                string `json:"dataURL"`
	SignURL                string `json:"signURL"`
}

func (p relayProfile) registerPath() string {
	if p.cfg.OrgID != "" {
		return fmt.Sprintf("%s/api/%s/egovQr", p.cfg.BaseURL, p.cfg.OrgID)
	}
	return p.cfg.BaseURL + "/api/egovQr"
}

func (p relayProfile) Prepare(ctx context.Context, s *Session, _ PublicURLs) (Artifacts, error) {
	// 1. Register the procedure.
	reg, err := p.postJSON(ctx, p.registerPath(), map[string]any{"description": s.Description})
	if err != nil {
		return Artifacts{}, fmt.Errorf("qr relay: register: %w", err)
	}
	var r registerResp
	if err := json.Unmarshal(reg, &r); err != nil {
		return Artifacts{}, fmt.Errorf("qr relay: decode register: %w", err)
	}
	if r.DataURL == "" {
		return Artifacts{}, fmt.Errorf("qr relay: gateway returned no dataURL")
	}

	// 2. Upload the documents to sign.
	up, err := p.postJSON(ctx, r.DataURL, map[string]any{
		"signMethod":      s.SignMethod,
		"documentsToSign": egovDocsFor(s),
	})
	if err != nil {
		return Artifacts{}, fmt.Errorf("qr relay: upload: %w", err)
	}
	var ur registerResp
	_ = json.Unmarshal(up, &ur) // upload echoes a (possibly refreshed) signURL
	signURL := firstStr(ur.SignURL, r.SignURL)
	s.RelaySignURL = signURL
	s.RelayID = r.QRCode

	return Artifacts{
		Payload:          r.QRCode,
		EGovMobileLink:   r.EGovMobileLaunchLink,
		EGovBusinessLink: r.EGovBusinessLaunchLink,
		DataURL:          r.DataURL,
		SignURL:          signURL,
	}, nil
}

// AppData / ParseAppSignature are unused: eGov Mobile talks to the upstream
// gateway, not to us.
func (relayProfile) AppData(*Session) (any, error)                      { return nil, ErrAppOnly }
func (relayProfile) ParseAppSignature(*Session, []byte) ([]byte, error) { return nil, ErrAppOnly }

// pollResp is the gateway's signature-poll response.
type pollResp struct {
	Status          string `json:"status"`
	DocumentsToSign []struct {
		Signature []byte `json:"signature"`
		CMS       []byte `json:"cms"`
		Document  struct {
			File struct {
				Data []byte `json:"data"`
			} `json:"file"`
		} `json:"document"`
	} `json:"documentsToSign"`
}

func (p relayProfile) Poll(ctx context.Context, s *Session) ([]byte, bool, error) {
	if s.RelaySignURL == "" {
		return nil, false, fmt.Errorf("qr relay: no upstream signURL")
	}
	body, err := p.get(ctx, s.RelaySignURL)
	if err != nil {
		return nil, false, err
	}
	var r pollResp
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, false, fmt.Errorf("qr relay: decode poll: %w", err)
	}
	for _, d := range r.DocumentsToSign {
		switch {
		case len(d.Signature) > 0:
			return d.Signature, true, nil
		case len(d.CMS) > 0:
			return d.CMS, true, nil
		case len(d.Document.File.Data) > 0:
			return d.Document.File.Data, true, nil
		}
	}
	// A canceled/expired upstream procedure is terminal with no signature.
	if strings.EqualFold(r.Status, "CANCELED") || strings.EqualFold(r.Status, "EXPIRED") {
		return nil, true, ErrSignatureRejected
	}
	return nil, false, nil
}

func (p relayProfile) postJSON(ctx context.Context, url string, payload any) ([]byte, error) {
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return p.do(req)
}

func (p relayProfile) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return p.do(req)
}

func (p relayProfile) do(req *http.Request) ([]byte, error) {
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gateway %s: status %d", req.URL.Path, resp.StatusCode)
	}
	return body, nil
}

// egovDocsFor builds the documentsToSign array shared by the egov and relay
// profiles from a session.
func egovDocsFor(s *Session) []egovDoc {
	docs := s.Documents
	if len(docs) == 0 && len(s.Data) > 0 {
		docs = []Document{{NameRu: s.Description, Data: s.Data, MIME: "@file/octet-stream"}}
	}
	out := make([]egovDoc, 0, len(docs))
	for i, d := range docs {
		var e egovDoc
		e.ID = i + 1
		e.NameRu, e.NameKz, e.NameEn = d.NameRu, d.NameKz, d.NameEn
		e.Document.File.MIME = d.MIME
		e.Document.File.Data = d.Data
		out = append(out, e)
	}
	return out
}

func firstStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
