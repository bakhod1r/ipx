package ipx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// SafeDialer dials only addresses that pass an SSRF check. It resolves the
// host itself, rejects the whole connection if ANY resolved address is
// blocked (so a mixed public/internal answer cannot win a race), and then
// connects to the checked IP, never re-resolving the name. That closes the
// DNS-rebinding window between check and connect.
//
// Plug it into http.Transport.DialContext for outbound fetches of
// user-supplied URLs. Redirects are covered because every hop dials anew.
type SafeDialer struct {
	// Dialer performs the connection; zero value uses net.Dialer defaults.
	Dialer net.Dialer
	// Lookup resolves host names; nil uses net.DefaultResolver.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// Allow, when set, overrides the default policy: an address is permitted
	// iff Allow allows it. When nil, IsInternal addresses are blocked.
	Allow *ACL
}

func (d *SafeDialer) permitted(a netip.Addr) bool {
	if d.Allow != nil {
		return d.Allow.Allowed(a)
	}
	return !IsInternal(a)
}

// DialContext has the signature of net.Dialer.DialContext.
func (d *SafeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		lookup := d.Lookup
		if lookup == nil {
			lookup = func(ctx context.Context, h string) ([]netip.Addr, error) {
				return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
			}
		}
		if addrs, err = lookup(ctx, host); err != nil {
			return nil, err
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("ipx: no addresses for %q", host)
		}
	}
	for _, a := range addrs {
		if !d.permitted(a) {
			return nil, fmt.Errorf("%w: %s resolves to %s", ErrBlockedAddr, host, a)
		}
	}
	var errs []error
	for _, a := range addrs {
		c, err := d.Dialer.DialContext(ctx, network, net.JoinHostPort(Normalize(a).String(), port))
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}
