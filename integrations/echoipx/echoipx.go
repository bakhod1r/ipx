// Package echoipx adapts ipx/httpip to Echo v4: trusted-proxy client IP
// resolution and ACL enforcement.
package echoipx

import (
	"net/http"
	"net/netip"

	"github.com/bakhod1r/ipx"
	"github.com/bakhod1r/ipx/httpip"
	"github.com/labstack/echo/v4"
)

const key = "ipx.clientIP"

// ClientIP stores the resolved client IP in the echo context. Requests whose
// peer cannot be parsed continue without one.
func ClientIP(res *httpip.Resolver) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if a, err := res.ClientIP(c.Request()); err == nil {
				c.Set(key, a)
			}
			return next(c)
		}
	}
}

// Restrict responds 403 unless acl allows the client IP.
func Restrict(res *httpip.Resolver, acl *ipx.ACL) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			a, err := res.ClientIP(c.Request())
			if err != nil || !acl.Allowed(a) {
				return echo.NewHTTPError(http.StatusForbidden)
			}
			c.Set(key, a)
			return next(c)
		}
	}
}

// FromContext returns the IP stored by ClientIP or Restrict.
func FromContext(c echo.Context) (netip.Addr, bool) {
	a, ok := c.Get(key).(netip.Addr)
	return a, ok
}
