# ipx

[![ci](https://github.com/bakhod1r/ipx/actions/workflows/ci.yml/badge.svg)](https://github.com/bakhod1r/ipx/actions/workflows/ci.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/bakhod1r/ipx.svg)](https://pkg.go.dev/github.com/bakhod1r/ipx) · [Website](https://bakhod1r.github.io/ipx/)

Dependency-free IP networking toolkit for Go, built on `net/netip`.

```sh
go get github.com/bakhod1r/ipx
go install github.com/bakhod1r/ipx/cmd/ipx@latest
```

## Features

| Area | API |
|---|---|
| Parsing / validation | `ParseAddr`, `ParsePrefix`, `ParsePrefixStrict`, `ParseNetwork`, `ParseRange`, `ParseIPSet`, `ParseAddrs`, `Normalize`, `NormalizePrefix` |
| Classification (IANA registries) | `IsPrivate`, `IsPublic`, `IsLoopback`, `IsLinkLocal`, `IsShared`, `IsDocumentation`, `IsBenchmarking`, `IsReserved`, `IsSpecial`, `Special`, `IsIPv4Mapped`, `IsIPv4Compatible` |
| Arithmetic (128-bit) | `Next`, `Prev`, `Add`, `AddBig`, `Distance`, `Offset`, `Nth`, `ToBig`, `FromBig`, `IPv4ToUint32`, `ToHex`, `ExpandIPv6` |
| CIDR | `First`, `Last`, `Broadcast`, `FirstUsable`, `LastUsable`, `Size`, `UsableHosts`, `Netmask`, `Hostmask`, `PrefixFromMask`, `Parent`, `Children`, `Sibling`, `Supernet`, `Adjacent`, `CommonPrefix`, `CommonAncestor`, `IntersectPrefix` |
| Subnetting | `Split` (lazy iterator), `SplitN`, `SubnetCount`, `SubnetIndex`, `Hosts`, `PrefixLenForHosts`, `PlanSubnets` (VLSM) |
| Ranges | `Range`: `Contains`, `Overlaps`, `Intersect`, `Merge`, `Subtract`, `Prefixes`, `All`, `Walk(ctx)`, `SplitRange`, `MergeRanges` |
| Sets | immutable `IPSet`: `Union`, `Intersect`, `Difference`, `SymmetricDifference`, `Complement`, `Prefixes`; `Aggregate`, `SubtractPrefixes` |
| Longest-prefix match | `Table[V]` trie, `SyncTable[V]` |
| ACL | `ACL` with `LongestPrefix` / `FirstMatch`, priorities, groups; `Allowlist`, `Denylist` |
| Allocation | `Allocator`: sequential, reverse, random, `Reserve`, `Claim`, `Release`, exclusions |
| DNS | `ReverseName`, `ParseReverseName`, `ReverseZones`, `RFC2317Zone`, `RFC2317CNAMEs` |
| Endpoints | `ParseEndpoint`, `ParsePort`, `SplitHostPort`, `ParseHost`, `FormatEndpoint` |
| Security (SSRF) | `IsInternal`, `IsCloudMetadata`, `EmbeddedIPv4` (mapped / compatible / NAT64 / 6to4), `SafeDialer` (rebinding-safe) |
| Inspection | `InspectAddr`, `InspectPrefix` |
| Hierarchy | `FindOverlaps`, `BuildTree` |
| Batch | `IPSet.ContainsBatch`, `Table.LookupBatch`, `ParseAddrs`, `ParsePrefixes` |
| Kubernetes (`ipx/k8s`) | `Networks.Validate` (pod/service/node overlap), `NodeCIDRs`, `MaxNodes`, `ServiceIP`, `APIServerIP`, `DNSServiceIP` |
| HTTP (`ipx/httpip`) | trusted-proxy client IP, context middleware, ACL `Restrict`, transport-agnostic `Resolve` |
| SQL (`ipx/sqlip`) | `database/sql` Scanner/Valuer: `Addr`, `Prefix` (Postgres `inet`/`cidr`, text), `BinaryAddr` (MySQL `VARBINARY(16)`) |
| Cloud ranges (`ipx/cloud`) | fetch AWS / Google Cloud / Cloudflare published ranges; `Index.Lookup` → provider, region, service |

## Examples

```go
ipx.Aggregate([]netip.Prefix{P("10.0.0.0/25"), P("10.0.0.128/25")}) // [10.0.0.0/24]
ipx.SubtractPrefixes([]netip.Prefix{P("10.0.0.0/24")}, []netip.Prefix{P("10.0.0.0/25")}) // [10.0.0.128/25]

var rt ipx.Table[string]
rt.Insert(P("10.0.0.0/8"), "a"); rt.Insert(P("10.10.10.0/24"), "c")
p, v, _ := rt.Lookup(A("10.10.10.50")) // 10.10.10.0/24 "c"

ipx.IsInternal(A("::ffff:169.254.169.254")) // true — mapped form cannot bypass
```

```sh
ipx split 192.168.1.0/24 26
ipx diff 10.0.0.0/24 10.0.0.0/25
ipx info 2001:db8::1
ipx plan 10.0.0.0/24 hosts:100 hosts:50 27   # VLSM
ipx alloc 10.0.0.0/24 5 --reserve 10.0.0.1
ipx --json cidr 10.0.0.0/22                  # machine-readable output
```

## Performance

vs [`go4.org/netipx`](https://pkg.go.dev/go4.org/netipx) (Apple M-series, `cd bench && go test -bench .`):

| Operation | ipx | netipx |
|---|---|---|
| `IPSet.Contains`, 10k ranges | 89 ns, 0 allocs | 90 ns, 0 allocs |
| `Range.Prefixes` (10.0.0.5–10.200.3.77) | 765 ns | 1035 ns |
| `IPSet` build, 10k prefixes | ~1.7–2.3 ms | ~1.6 ms |

## Guarantees

- No panics on user input (`Must*` helpers excepted); errors match with `errors.Is`.
- IPv4-mapped IPv6 is unmapped before classification, set membership and ACL checks.
- `IPSet`, `Range` immutable; `ACL`, `Allocator`, `SyncTable` goroutine-safe; `Table` single-writer.
- IPv4 `/31` and `/32` follow RFC 3021 (all addresses usable).
- 100% statement coverage, enforced in CI.

## Integrations (separate modules)

Kept out of the core module so `go get github.com/bakhod1r/ipx` stays dependency-free.

| Module | Purpose |
|---|---|
| `github.com/bakhod1r/ipx/integrations/ginipx` | Gin: `ClientIP`, `Restrict`, `FromContext` |
| `github.com/bakhod1r/ipx/integrations/echoipx` | Echo v4: same API |
| `github.com/bakhod1r/ipx/integrations/fiberipx` | Fiber v3 (fasthttp): same API |
| `github.com/bakhod1r/ipx/integrations/geoip` | MaxMind MMDB: `Country`, `ASN`, generic `Lookup` (databases not bundled — GeoLite2 has its own license) |

## License

MIT — see [LICENSE](LICENSE).
