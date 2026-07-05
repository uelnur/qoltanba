package qr

import (
	"context"
	"encoding/json"
	"strings"
)

// EGovConfig tunes the self-hosted eGov gateway profile. The exact string eGov
// Mobile expects inside the QR (and the launch-link scheme) is documented on
// eGov's Smart Bridge behind service registration; these templates default to the
// bare public data URL and are overridable so an operator who has registered can
// match the live format without a code change. Placeholders: {dataUrl}, {signUrl},
// {id}.
type EGovConfig struct {
	PayloadTemplate      string // QR content; default "{dataUrl}"
	MobileLinkTemplate   string // eGovMobileLaunchLink; default "" (omitted)
	BusinessLinkTemplate string // eGovBusinessLaunchLink; default ""
	Organization         string // display name shown in eGov Mobile
}

// egovProfile hosts the eGov QR gateway contract ourselves: AppData serves the
// documented documentsToSign structure and ParseAppSignature reads the signature
// back from it.
type egovProfile struct {
	cfg EGovConfig
}

// NewEGovProfile builds the self-hosted eGov gateway profile.
func NewEGovProfile(cfg EGovConfig) Profiler { return newEGovProfile(cfg) }

func newEGovProfile(cfg EGovConfig) egovProfile {
	if cfg.PayloadTemplate == "" {
		cfg.PayloadTemplate = "{dataUrl}"
	}
	return egovProfile{cfg: cfg}
}

func (egovProfile) SelfHosted() bool { return true }

func (p egovProfile) Prepare(_ context.Context, s *Session, urls PublicURLs) (Artifacts, error) {
	rep := strings.NewReplacer("{dataUrl}", urls.DataURL, "{signUrl}", urls.SignURL, "{id}", s.ID)
	a := Artifacts{
		Payload: rep.Replace(p.cfg.PayloadTemplate),
		DataURL: urls.DataURL,
		SignURL: urls.SignURL,
	}
	if p.cfg.MobileLinkTemplate != "" {
		a.EGovMobileLink = rep.Replace(p.cfg.MobileLinkTemplate)
	}
	if p.cfg.BusinessLinkTemplate != "" {
		a.EGovBusinessLink = rep.Replace(p.cfg.BusinessLinkTemplate)
	}
	return a, nil
}

// egovDoc mirrors the eGov/SIGEX documentsToSign item shape.
type egovDoc struct {
	ID       int    `json:"id"`
	NameRu   string `json:"nameRu,omitempty"`
	NameKz   string `json:"nameKz,omitempty"`
	NameEn   string `json:"nameEn,omitempty"`
	Document struct {
		File struct {
			MIME string `json:"mime,omitempty"`
			Data []byte `json:"data"` // base64
		} `json:"file"`
	} `json:"document"`
}

func (p egovProfile) AppData(s *Session) (any, error) {
	docs := s.Documents
	if len(docs) == 0 {
		if len(s.Data) == 0 {
			return nil, ErrNoData
		}
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
	return map[string]any{
		"signMethod":      s.SignMethod,
		"organization":    p.cfg.Organization,
		"documentsToSign": out,
	}, nil
}

// ParseAppSignature reads the returned signature. eGov Mobile posts the signed
// documentsToSign back; the detached CMS/XML lives in the first document's
// signature. We accept both the documented nested shape and a bare {signature}
// for flexibility across gateway versions.
func (egovProfile) ParseAppSignature(_ *Session, body []byte) ([]byte, error) {
	var flat struct {
		Signature []byte `json:"signature"`
	}
	if err := json.Unmarshal(body, &flat); err == nil && len(flat.Signature) > 0 {
		return flat.Signature, nil
	}
	var nested struct {
		DocumentsToSign []struct {
			Signature []byte `json:"signature"`
			CMS       []byte `json:"cms"`
		} `json:"documentsToSign"`
	}
	if err := json.Unmarshal(body, &nested); err != nil {
		return nil, err
	}
	for _, d := range nested.DocumentsToSign {
		switch {
		case len(d.Signature) > 0:
			return d.Signature, nil
		case len(d.CMS) > 0:
			return d.CMS, nil
		}
	}
	return nil, ErrSignatureRejected
}

func (egovProfile) Poll(context.Context, *Session) ([]byte, bool, error) {
	return nil, false, ErrAppOnly
}
