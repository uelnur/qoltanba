package qr

import "context"

// PublicURLs are the externally reachable app-facing URLs for a session, built by
// the transport from the configured public base (or X-Forwarded headers) so they
// are correct behind the consumer's reverse proxy.
type PublicURLs struct {
	DataURL string // eGov Mobile GETs the data-to-sign here
	SignURL string // eGov Mobile POSTs the signature here
}

// Artifacts are what a profile produces for a new session: the raw QR content and
// the effective links. DataURL/SignURL echo back the URLs the app will use (our
// own for self-hosted profiles, the upstream gateway's for relay).
type Artifacts struct {
	Payload          string
	EGovMobileLink   string
	EGovBusinessLink string
	DataURL          string
	SignURL          string
}

// Profiler encapsulates how one profile bridges to eGov Mobile. Self-hosted
// profiles (agnostic, egov) host the app-facing endpoints and implement
// AppData/ParseAppSignature; relay profiles delegate to an upstream gateway and
// implement Poll instead.
type Profiler interface {
	// SelfHosted reports whether the service hosts the app-facing data/sign
	// endpoints for this profile (true) or delegates to an upstream gateway (false).
	SelfHosted() bool
	// Prepare builds the QR payload and links for a new session. For relay it also
	// registers the procedure and uploads the documents to the upstream gateway,
	// stamping RelayID/RelaySignURL on the session.
	Prepare(ctx context.Context, s *Session, urls PublicURLs) (Artifacts, error)
	// AppData renders the data-to-sign body eGov Mobile fetches (self-hosted).
	AppData(s *Session) (any, error)
	// ParseAppSignature extracts the CMS/XML signature from the app's POST body
	// (self-hosted).
	ParseAppSignature(s *Session, body []byte) ([]byte, error)
	// Poll pulls the signature from the upstream gateway (relay); done=false means
	// keep waiting.
	Poll(ctx context.Context, s *Session) (sig []byte, done bool, err error)
}
