// Package ginipx adapts ipx/httpip to Gin: trusted-proxy client IP
// resolution and ACL enforcement. Use it instead of gin's ClientIP when you
// need explicit, auditable proxy trust.
package ginipx

import (
	"net/http"
	"net/netip"

	"github.com/bakhod1r/ipx"
	"github.com/bakhod1r/ipx/httpip"
	"github.com/gin-gonic/gin"
)

const key = "ipx.clientIP"

// ClientIP stores the resolved client IP in the gin context. Requests whose
// peer cannot be parsed continue without one.
func ClientIP(res *httpip.Resolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		if a, err := res.ClientIP(c.Request); err == nil {
			c.Set(key, a)
		}
		c.Next()
	}
}

// Restrict aborts with 403 unless acl allows the client IP.
func Restrict(res *httpip.Resolver, acl *ipx.ACL) gin.HandlerFunc {
	return func(c *gin.Context) {
		a, err := res.ClientIP(c.Request)
		if err != nil || !acl.Allowed(a) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Set(key, a)
		c.Next()
	}
}

// FromContext returns the IP stored by ClientIP or Restrict.
func FromContext(c *gin.Context) (netip.Addr, bool) {
	v, ok := c.Get(key)
	if !ok {
		return netip.Addr{}, false
	}
	a, ok := v.(netip.Addr)
	return a, ok
}
