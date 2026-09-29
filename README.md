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
| DNS | `ReverseName`, `ParseReverseName`, `ReverseZones` |
| Endpoints | `ParseEndpoint`, `ParsePort`, `SplitHostPort`, `ParseHost`, `FormatEndpoint` |
| Security (SSRF) | `IsInternal`, `IsCloudMetadata`, `EmbeddedIPv4` (mapped / compatible / NAT64 / 6to4), `SafeDialer` (rebinding-safe) |
| Inspection | `InspectAddr`, `InspectPrefix` |
| HTTP (`ipx/httpip`) | trusted-proxy client IP, context middleware, ACL `Restrict` |

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
```

## Guarantees

- No panics on user input (`Must*` helpers excepted); errors match with `errors.Is`.
- IPv4-mapped IPv6 is unmapped before classification, set membership and ACL checks.
- `IPSet`, `Range` immutable; `ACL`, `Allocator`, `SyncTable` goroutine-safe; `Table` single-writer.
- IPv4 `/31` and `/32` follow RFC 3021 (all addresses usable).

## Not included (by design)

Framework middleware (Gin/Echo/Fiber), PostgreSQL/MySQL scanners and Kubernetes helpers pull in dependencies; they belong in separate modules.
