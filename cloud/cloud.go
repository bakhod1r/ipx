// Package cloud fetches the IP ranges that cloud providers publish (AWS,
// Google Cloud, Cloudflare) and answers "which provider/region owns this
// address?". Standard library only. Nothing is fetched at import time;
// callers decide when to refresh and should cache the result.
package cloud

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/bakhod1r/ipx"
)

// Provider names a cloud.
type Provider string

const (
	AWS        Provider = "aws"
	GCP        Provider = "gcp"
	Cloudflare Provider = "cloudflare"
)

// Official feed locations.
const (
	DefaultAWSURL          = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	DefaultGCPURL          = "https://www.gstatic.com/ipranges/cloud.json"
	DefaultCloudflareV4URL = "https://www.cloudflare.com/ips-v4"
	DefaultCloudflareV6URL = "https://www.cloudflare.com/ips-v6"

	defaultMaxBytes = 32 << 20
)

// Entry is one published prefix.
type Entry struct {
	Prefix   netip.Prefix
	Provider Provider
	Region   string // empty when the feed has none
	Service  string
}

// Fetcher downloads feeds. The zero value uses http.DefaultClient and the
// official URLs; override fields for proxies, mirrors or tests.
type Fetcher struct {
	Client                           *http.Client
	AWSURL, GCPURL                   string
	CloudflareV4URL, CloudflareV6URL string
	// MaxBytes caps each response body (default 32 MiB).
	MaxBytes int64
}

func (f *Fetcher) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return http.DefaultClient
}

func (f *Fetcher) url(set, def string) string {
	if set != "" {
		return set
	}
	return def
}

func (f *Fetcher) limit() int64 {
	if f.MaxBytes > 0 {
		return f.MaxBytes
	}
	return defaultMaxBytes
}

func (f *Fetcher) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloud: GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.limit()+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > f.limit() {
		return nil, fmt.Errorf("cloud: GET %s: body exceeds %d bytes", url, f.limit())
	}
	return body, nil
}

func parse(s string, p Provider) (netip.Prefix, error) {
	pr, err := ipx.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("cloud: %s feed: %w", p, err)
	}
	return pr.Masked(), nil
}

// AWS fetches ip-ranges.json.
func (f *Fetcher) AWS(ctx context.Context) ([]Entry, error) {
	body, err := f.get(ctx, f.url(f.AWSURL, DefaultAWSURL))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Region   string `json:"region"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Region     string `json:"region"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("cloud: aws feed: %w", err)
	}
	out := make([]Entry, 0, len(doc.Prefixes)+len(doc.IPv6Prefixes))
	for _, x := range doc.Prefixes {
		p, err := parse(x.IPPrefix, AWS)
		if err != nil {
			return nil, err
		}
		out = append(out, Entry{p, AWS, x.Region, x.Service})
	}
	for _, x := range doc.IPv6Prefixes {
		p, err := parse(x.IPv6Prefix, AWS)
		if err != nil {
			return nil, err
		}
		out = append(out, Entry{p, AWS, x.Region, x.Service})
	}
	return out, nil
}

// GCP fetches Google Cloud's cloud.json (customer-usable ranges).
func (f *Fetcher) GCP(ctx context.Context) ([]Entry, error) {
	body, err := f.get(ctx, f.url(f.GCPURL, DefaultGCPURL))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Prefixes []struct {
			IPv4    string `json:"ipv4Prefix"`
			IPv6    string `json:"ipv6Prefix"`
			Service string `json:"service"`
			Scope   string `json:"scope"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("cloud: gcp feed: %w", err)
	}
	out := make([]Entry, 0, len(doc.Prefixes))
	for _, x := range doc.Prefixes {
		p, err := parse(x.IPv4+x.IPv6, GCP)
		if err != nil {
			return nil, err
		}
		out = append(out, Entry{p, GCP, x.Scope, x.Service})
	}
	return out, nil
}

// Cloudflare fetches the plain-text ips-v4 and ips-v6 lists.
func (f *Fetcher) Cloudflare(ctx context.Context) ([]Entry, error) {
	var out []Entry
	for _, u := range []string{f.url(f.CloudflareV4URL, DefaultCloudflareV4URL), f.url(f.CloudflareV6URL, DefaultCloudflareV6URL)} {
		body, err := f.get(ctx, u)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(bytes.NewReader(body))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			p, err := parse(line, Cloudflare)
			if err != nil {
				return nil, err
			}
			out = append(out, Entry{Prefix: p, Provider: Cloudflare, Service: "CLOUDFLARE"})
		}
	}
	return out, nil
}

// All fetches every provider; the first error aborts.
func (f *Fetcher) All(ctx context.Context) ([]Entry, error) {
	var out []Entry
	for _, fetch := range []func(context.Context) ([]Entry, error){f.AWS, f.GCP, f.Cloudflare} {
		es, err := fetch(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, es...)
	}
	return out, nil
}

// Index answers ownership queries. Immutable after NewIndex; safe for
// concurrent use.
type Index struct {
	table ipx.Table[Entry]
	sets  map[Provider]*ipx.IPSet
}

// NewIndex builds an index. When prefixes repeat, the last entry wins.
func NewIndex(entries []Entry) *Index {
	idx := &Index{sets: map[Provider]*ipx.IPSet{}}
	byProvider := map[Provider][]netip.Prefix{}
	for _, e := range entries {
		idx.table.Insert(e.Prefix, e)
		byProvider[e.Provider] = append(byProvider[e.Provider], e.Prefix)
	}
	for p, ps := range byProvider {
		idx.sets[p] = ipx.NewIPSet(ps)
	}
	return idx
}

// Lookup returns the most specific entry containing a.
func (idx *Index) Lookup(a netip.Addr) (Entry, bool) {
	_, e, ok := idx.table.Lookup(a)
	return e, ok
}

// Set returns every address published by provider p (empty if unknown).
func (idx *Index) Set(p Provider) *ipx.IPSet {
	if s, ok := idx.sets[p]; ok {
		return s
	}
	return &ipx.IPSet{}
}
