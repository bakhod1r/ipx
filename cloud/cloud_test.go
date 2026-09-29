package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

const awsJSON = `{"prefixes":[{"ip_prefix":"3.5.140.0/22","region":"ap-northeast-2","service":"AMAZON"},
{"ip_prefix":"3.5.140.0/24","region":"ap-northeast-2","service":"S3"}],
"ipv6_prefixes":[{"ipv6_prefix":"2600:1f14::/35","region":"eu-west-1","service":"EC2"}]}`

const gcpJSON = `{"prefixes":[{"ipv4Prefix":"34.1.208.0/20","service":"Google Cloud","scope":"africa-south1"},
{"ipv6Prefix":"2600:1900:8000::/44","service":"Google Cloud","scope":"us-east1"}]}`

func server(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/aws", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(awsJSON)) })
	mux.HandleFunc("/gcp", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(gcpJSON)) })
	mux.HandleFunc("/cf4", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("173.245.48.0/20\n103.21.244.0/22\n")) })
	mux.HandleFunc("/cf6", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("2400:cb00::/32\n\n")) })
	mux.HandleFunc("/bad6", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"ipv6_prefixes":[{"ipv6_prefix":"nope"}]}`))
	})
	mux.HandleFunc("/truncated", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Write([]byte("{"))
	})
	mux.HandleFunc("/bad", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("{not json")) })
	mux.HandleFunc("/badcidr", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"prefixes":[{"ip_prefix":"nope"}]}`)) })
	mux.HandleFunc("/500", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", 500) })
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(strings.Repeat(" ", 100))) })
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func TestFetchAndLookup(t *testing.T) {
	s := server(t)
	f := &Fetcher{Client: s.Client(), AWSURL: s.URL + "/aws", GCPURL: s.URL + "/gcp",
		CloudflareV4URL: s.URL + "/cf4", CloudflareV6URL: s.URL + "/cf6"}
	ctx := context.Background()
	aws, err := f.AWS(ctx)
	if err != nil || len(aws) != 3 || aws[2].Prefix != netip.MustParsePrefix("2600:1f14::/35") || aws[2].Provider != AWS {
		t.Fatal(aws, err)
	}
	gcp, err := f.GCP(ctx)
	if err != nil || len(gcp) != 2 || gcp[0].Region != "africa-south1" {
		t.Fatal(gcp, err)
	}
	cf, err := f.Cloudflare(ctx)
	if err != nil || len(cf) != 3 || cf[2].Provider != Cloudflare {
		t.Fatal(cf, err)
	}
	all, err := f.All(ctx)
	if err != nil || len(all) != 8 {
		t.Fatal(len(all), err)
	}
	idx := NewIndex(all)
	e, ok := idx.Lookup(netip.MustParseAddr("3.5.140.9"))
	if !ok || e.Service != "S3" { // most specific wins
		t.Error(e)
	}
	if e, ok := idx.Lookup(netip.MustParseAddr("::ffff:173.245.48.1")); !ok || e.Provider != Cloudflare {
		t.Error("mapped lookup", e)
	}
	if _, ok := idx.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Error("false positive")
	}
	if !idx.Set("azure").IsEmpty() {
		t.Error("unknown provider set")
	}
	if !idx.Set(Cloudflare).Contains(netip.MustParseAddr("2400:cb00::1")) || idx.Set(AWS).Contains(netip.MustParseAddr("2400:cb00::1")) {
		t.Error("Set")
	}
}

func TestFetchErrors(t *testing.T) {
	s := server(t)
	ctx := context.Background()
	for name, f := range map[string]*Fetcher{
		"status":  {Client: s.Client(), AWSURL: s.URL + "/500"},
		"json":    {Client: s.Client(), AWSURL: s.URL + "/bad"},
		"cidr":    {Client: s.Client(), AWSURL: s.URL + "/badcidr"},
		"limit":   {Client: s.Client(), AWSURL: s.URL + "/big", MaxBytes: 10},
		"url":     {Client: s.Client(), AWSURL: "::bad"},
		"v6":      {Client: s.Client(), AWSURL: s.URL + "/bad6"},
		"body":    {Client: s.Client(), AWSURL: s.URL + "/truncated"},
		"network": {Client: s.Client(), AWSURL: "http://127.0.0.1:1/x"},
	} {
		if _, err := f.AWS(ctx); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	bad := &Fetcher{Client: s.Client(), GCPURL: s.URL + "/badcidr", CloudflareV4URL: s.URL + "/aws", CloudflareV6URL: s.URL + "/500"}
	if _, err := bad.GCP(ctx); err == nil {
		t.Error("gcp empty prefix accepted")
	}
	if _, err := bad.Cloudflare(ctx); err == nil {
		t.Error("cloudflare bad body accepted")
	}
	bad.CloudflareV4URL = s.URL + "/cf4"
	if _, err := bad.Cloudflare(ctx); err == nil {
		t.Error("cloudflare v6 500 accepted")
	}
	if _, err := (&Fetcher{Client: s.Client(), AWSURL: s.URL + "/500"}).All(ctx); err == nil {
		t.Error("All swallowed error")
	}
	if _, err := (&Fetcher{Client: s.Client(), AWSURL: s.URL + "/aws", GCPURL: s.URL + "/500"}).All(ctx); err == nil {
		t.Error("All swallowed gcp error")
	}
	gcpBad := &Fetcher{Client: s.Client(), GCPURL: s.URL + "/bad"}
	if _, err := gcpBad.GCP(ctx); err == nil {
		t.Error("gcp bad json")
	}
	gcpBad.GCPURL = s.URL + "/500"
	if _, err := gcpBad.GCP(ctx); err == nil {
		t.Error("gcp 500")
	}
}

func TestDefaults(t *testing.T) {
	var f Fetcher
	if f.client() != http.DefaultClient || f.url("", "d") != "d" || f.url("x", "d") != "x" || f.limit() != defaultMaxBytes {
		t.Error("defaults")
	}
}
