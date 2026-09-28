package httpip

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/bakhod1r/ipx"
)

func req(remote string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestClientIP(t *testing.T) {
	res := New(netip.MustParsePrefix("10.0.0.0/8"))
	cases := []struct {
		name, remote string
		hdr          map[string]string
		want         string
	}{
		{"no proxy", "203.0.113.9:1234", nil, "203.0.113.9"},
		{"untrusted peer spoofs XFF", "203.0.113.9:1234", map[string]string{"X-Forwarded-For": "1.1.1.1"}, "203.0.113.9"},
		{"trusted proxy", "10.0.0.2:80", map[string]string{"X-Forwarded-For": "198.51.100.7"}, "198.51.100.7"},
		{"chain, rightmost untrusted wins", "10.0.0.2:80", map[string]string{"X-Forwarded-For": "6.6.6.6, 198.51.100.7, 10.0.0.3"}, "198.51.100.7"},
		{"all trusted, leftmost", "10.0.0.2:80", map[string]string{"X-Forwarded-For": "10.1.1.1, 10.0.0.3"}, "10.1.1.1"},
		{"garbage in chain stops walk", "10.0.0.2:80", map[string]string{"X-Forwarded-For": "1.1.1.1, junk"}, "10.0.0.2"},
		{"x-real-ip from trusted", "10.0.0.2:80", map[string]string{"X-Real-IP": "198.51.100.8"}, "198.51.100.8"},
		{"mapped peer normalized", "[::ffff:10.0.0.2]:80", map[string]string{"X-Forwarded-For": "[2001:db8::1]:443"}, "2001:db8::1"},
		{"ipv6 remote", "[2001:db8::5]:80", nil, "2001:db8::5"},
	}
	for _, c := range cases {
		got, err := res.ClientIP(req(c.remote, c.hdr))
		if err != nil || got != netip.MustParseAddr(c.want) {
			t.Errorf("%s: got %v, %v want %s", c.name, got, err, c.want)
		}
	}
	if _, err := res.ClientIP(req("bogus", nil)); err == nil {
		t.Error("bad RemoteAddr accepted")
	}
}

func TestMiddleware(t *testing.T) {
	var seen netip.Addr
	h := New().Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = FromContext(r.Context())
	}))
	h.ServeHTTP(httptest.NewRecorder(), req("198.51.100.1:5", nil))
	if seen != netip.MustParseAddr("198.51.100.1") {
		t.Error(seen)
	}
}

func TestRestrict(t *testing.T) {
	acl := ipx.Allowlist(netip.MustParsePrefix("192.0.2.0/24"))
	h := New().Restrict(acl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for remote, code := range map[string]int{"192.0.2.5:1": 200, "198.51.100.1:1": 403, "junk": 403} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req(remote, nil))
		if rec.Code != code {
			t.Errorf("%s: %d", remote, rec.Code)
		}
	}
}
