package ocspcache

import "github.com/uelnur/qoltanba/internal/core"

// Adapter presents the cache as the domain's OCSPCache port. The conversion is
// explicit rather than the cache using the domain types directly, so the cache
// stays a self-contained piece with no dependency on the request contract.
type Adapter struct{ c *Cache }

var _ core.OCSPCache = Adapter{}

// Port wraps c for the domain.
func Port(c *Cache) Adapter { return Adapter{c: c} }

func (a Adapter) Lookup(certDER []byte, responder string) (core.OCSPAnswer, bool) {
	e, ok := a.c.Lookup(certDER, responder)
	if !ok {
		return core.OCSPAnswer{}, false
	}
	return core.OCSPAnswer(e), true
}

func (a Adapter) Store(certDER []byte, responder string, answer core.OCSPAnswer) {
	a.c.Store(certDER, responder, Entry(answer))
}
