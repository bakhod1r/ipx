// Package httpip resolves the real client IP of an HTTP request behind
// explicitly trusted proxies, and provides net/http middleware.
//
// Forwarding headers are honored only when the direct peer (RemoteAddr) is
// a trusted proxy. X-Forwarded-For is walked right to left, skipping trusted
// hops; the first untrusted hop is the client. Never trust the leftmost
// X-Forwarded-For entry blindly — any client can set it.
package httpip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/bakhod1r/ipx"
)

// Resolver extracts client IPs. Immutable after New; safe for concurrent use.
type Resolver struct {
	trusted *ipx.IPSet
}

// New returns a Resolver trusting the given proxy networks. With none,
// forwarding headers are ignored and RemoteAddr is used.
func New(trustedProxies ...netip.Prefix) *Resolver {
	return &Resolver{trusted: ipx.NewIPSet(trustedProxies)}
}

// ClientIP returns the normalized client address of r.
func (res *Resolver) ClientIP(r *http.Request) (netip.Addr, error) {
	peer, err := ipx.ParseHost(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, errors.Join(errors.New("httpip: bad RemoteAddr"), err)
	}
	if !res.trusted.Contains(peer) {
		return peer, nil
	}
	if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
		hops := strings.Split(strings.Join(xff, ","), ",")
		var leftmost netip.Addr
		for i := len(hops) - 1; i >= 0; i-- {
			a, err := ipx.ParseHost(strings.TrimSpace(hops[i]))
			if err != nil {
				return peer, nil //nolint:nilerr // malformed chain: fall back to the trusted peer
			}
			if !res.trusted.Contains(a) {
				return a, nil
			}
			leftmost = a
		}
		return leftmost, nil
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		if a, err := ipx.ParseHost(xr); err == nil {
			return a, nil
		}
	}
	return peer, nil
}

type ctxKey struct{}

// FromContext returns the client IP stored by Middleware.
func FromContext(ctx context.Context) (netip.Addr, bool) {
	a, ok := ctx.Value(ctxKey{}).(netip.Addr)
	return a, ok
}

// Middleware stores the client IP in the request context. Requests whose IP
// cannot be resolved pass through without one.
func (res *Resolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a, err := res.ClientIP(r); err == nil {
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, a))
		}
		next.ServeHTTP(w, r)
	})
}

// Restrict answers 403 unless acl allows the client IP.
func (res *Resolver) Restrict(acl *ipx.ACL, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := res.ClientIP(r)
		if err != nil || !acl.Allowed(a) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, a)))
	})
}
