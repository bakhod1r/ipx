package ginipx

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/bakhod1r/ipx"
	"github.com/bakhod1r/ipx/httpip"
	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

func do(h http.Handler, remote, xff string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestClientIP(t *testing.T) {
	e := gin.New()
	e.Use(ClientIP(httpip.New(netip.MustParsePrefix("10.0.0.0/8"))))
	e.GET("/", func(c *gin.Context) {
		a, ok := FromContext(c)
		if !ok {
			c.String(500, "missing")
			return
		}
		c.String(200, a.String())
	})
	if w := do(e, "10.0.0.2:1", "198.51.100.7"); w.Body.String() != "198.51.100.7" {
		t.Error(w.Body.String())
	}
	if w := do(e, "junk", ""); w.Code != 500 {
		t.Error("unresolvable peer should leave context empty", w.Code)
	}
}

func TestRestrict(t *testing.T) {
	e := gin.New()
	e.Use(Restrict(httpip.New(), ipx.Allowlist(netip.MustParsePrefix("192.0.2.0/24"))))
	e.GET("/", func(c *gin.Context) {
		a, _ := FromContext(c)
		c.String(200, a.String())
	})
	if w := do(e, "192.0.2.9:1", ""); w.Code != 200 || w.Body.String() != "192.0.2.9" {
		t.Error(w.Code, w.Body.String())
	}
	for _, remote := range []string{"198.51.100.1:1", "junk"} {
		if w := do(e, remote, ""); w.Code != 403 {
			t.Error(remote, w.Code)
		}
	}
}
