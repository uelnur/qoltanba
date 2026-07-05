package core

import "context"

// DataRef points at the payload to sign or verify by reference instead of inline,
// so a large file never rides in the request body (no +33% base64, no RAM spike).
// Exactly one of Path or URL is set; an empty DataRef means the inline Data is
// used. The resolver turns it into a local filesystem path the driver reads
// directly (KC_IN_FILE) — the library streams the file, nothing is buffered.
type DataRef struct {
	// Path is a local filesystem path. Reading arbitrary local paths is gated by
	// the resolver's policy (off by default) — a request must not be able to make
	// the service read any file it likes.
	Path string `json:"path,omitempty"`
	// URL is an https (or S3-presigned) source streamed to a private spool file.
	URL string `json:"url,omitempty"`
}

// IsRef reports whether the payload is by reference (Path or URL set).
func (r DataRef) IsRef() bool { return r.Path != "" || r.URL != "" }

// ResolvedData is a by-reference payload made locally readable: a filesystem path
// for the driver plus a cleanup to run when the operation is done (it removes a
// spool file the resolver created; it is a no-op for a caller-owned local path).
type ResolvedData struct {
	Path    string
	cleanup func()
}

// NewResolvedData builds a ResolvedData; cleanup may be nil.
func NewResolvedData(path string, cleanup func()) ResolvedData {
	return ResolvedData{Path: path, cleanup: cleanup}
}

// Release runs the cleanup (safe to call once, on any path including error/cancel).
func (r ResolvedData) Release() {
	if r.cleanup != nil {
		r.cleanup()
	}
}

// DataResolver turns a by-reference source into a local path the driver can read.
// It is infrastructure behind a domain-declared port (like KeySource): the domain
// depends on this interface, an adapter in main implements the scheme/size/path
// policy and the spooling. Nil means only inline data is accepted.
type DataResolver interface {
	Resolve(ctx context.Context, ref DataRef) (ResolvedData, error)
}
