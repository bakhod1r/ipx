// Package fiberipx adapts ipx/httpip to Fiber v3 (fasthttp): trusted-proxy
// client IP resolution and ACL enforcement.
package fiberipx

import (
	"net/netip"

	"github.com/bakhod1r/ipx"
	"github.com/bakhod1r/ipx/httpip"
	"github.com/gofiber/fiber/v3"
)

type ctxKey struct{}

func resolve(res *httpip.Resolver, c fiber.Ctx) (netip.Addr, error) {
	h := c.GetReqHeaders()
	var xr string
	if v := h["X-Real-Ip"]; len(v) > 0 {
		xr = v[0]
	}
	return res.Resolve(c.RequestCtx().RemoteAddr().String(), h["X-Forwarded-For"], xr)
}

// ClientIP stores the resolved client IP in Locals. Requests whose peer
// cannot be parsed continue without one.
func ClientIP(res *httpip.Resolver) fiber.Handler {
	return func(c fiber.Ctx) error {
		if a, err := resolve(res, c); err == nil {
			c.Locals(ctxKey{}, a)
		}
		return c.Next()
	}
}

// Restrict responds 403 unless acl allows the client IP.
func Restrict(res *httpip.Resolver, acl *ipx.ACL) fiber.Handler {
	return func(c fiber.Ctx) error {
		a, err := resolve(res, c)
		if err != nil || !acl.Allowed(a) {
			return c.SendStatus(fiber.StatusForbidden)
		}
		c.Locals(ctxKey{}, a)
		return c.Next()
	}
}

// FromContext returns the IP stored by ClientIP or Restrict.
func FromContext(c fiber.Ctx) (netip.Addr, bool) {
	a, ok := c.Locals(ctxKey{}).(netip.Addr)
	return a, ok
}
