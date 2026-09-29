package fiberipx

import (
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/bakhod1r/ipx"
	"github.com/bakhod1r/ipx/httpip"
	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
)

func handler(c fiber.Ctx) error {
	a, ok := FromContext(c)
	if !ok {
		return c.Status(500).SendString("missing")
	}
	return c.SendString(a.String())
}

// serve runs one request through app with a chosen peer address.
func serve(t *testing.T, app *fiber.App, peer, xff string) (int, string) {
	t.Helper()
	var addr net.Addr = &net.TCPAddr{IP: net.ParseIP(peer), Port: 1}
	if peer == "" {
		addr = badAddr{}
	}
	var req fasthttp.Request
	req.SetRequestURI("/")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	var rc fasthttp.RequestCtx
	rc.Init(&req, addr, nil)
	app.Handler()(&rc)
	return rc.Response.StatusCode(), string(rc.Response.Body())
}

type badAddr struct{}

func (badAddr) Network() string { return "tcp" }
func (badAddr) String() string  { return "junk" }

func TestClientIP(t *testing.T) {
	app := fiber.New()
	app.Use(ClientIP(httpip.New(netip.MustParsePrefix("10.0.0.0/8"))))
	app.Get("/", handler)
	if code, body := serve(t, app, "10.0.0.2", "6.6.6.6, 198.51.100.7"); code != 200 || body != "198.51.100.7" {
		t.Error(code, body)
	}
	app2 := fiber.New()
	app2.Use(ClientIP(httpip.New(netip.MustParsePrefix("10.0.0.0/8"))))
	app2.Get("/", handler)
	var req fasthttp.Request
	req.SetRequestURI("/")
	req.Header.Set("X-Real-IP", "198.51.100.8")
	var rc fasthttp.RequestCtx
	rc.Init(&req, &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 1}, nil)
	app2.Handler()(&rc)
	if string(rc.Response.Body()) != "198.51.100.8" {
		t.Error("X-Real-IP", string(rc.Response.Body()))
	}
	if code, _ := serve(t, app, "", ""); code != 500 {
		t.Error("unparseable peer should leave context empty", code)
	}
}

func TestRestrict(t *testing.T) {
	app := fiber.New()
	app.Use(Restrict(httpip.New(), ipx.Allowlist(netip.MustParsePrefix("192.0.2.0/24"))))
	app.Get("/", handler)
	if code, body := serve(t, app, "192.0.2.9", ""); code != 200 || body != "192.0.2.9" {
		t.Error(code, body)
	}
	for _, peer := range []string{"198.51.100.1", ""} {
		if code, _ := serve(t, app, peer, ""); code != 403 {
			t.Error(peer, code)
		}
	}
}

// Sanity: the real app.Test path works too.
func TestAppTest(t *testing.T) {
	app := fiber.New()
	app.Use(ClientIP(httpip.New()))
	app.Get("/", handler)
	resp, err := app.Test(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || len(b) == 0 {
		t.Error(resp.StatusCode, string(b))
	}
}
