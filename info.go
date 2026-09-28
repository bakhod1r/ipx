package ipx

import (
	"fmt"
	"math/big"
	"net/netip"
	"strings"
)

// AddrInfo is an immutable report about an address.
type AddrInfo struct {
	Addr       netip.Addr
	Version    int
	Public     bool
	Private    bool
	Loopback   bool
	Multicast  bool
	LinkLocal  bool
	Internal   bool
	Special    string // IANA block name, empty if none
	Reverse    string
	Hex        string
	Expanded   string
	EmbeddedV4 netip.Addr
}

// InspectAddr builds an AddrInfo.
func InspectAddr(a netip.Addr) (AddrInfo, error) {
	if !a.IsValid() {
		return AddrInfo{}, ErrInvalidAddr
	}
	n := Normalize(a)
	info := AddrInfo{
		Addr: n, Version: Family(n),
		Public: IsPublic(n), Private: IsPrivate(n), Loopback: IsLoopback(n),
		Multicast: IsMulticast(n), LinkLocal: IsLinkLocal(n), Internal: IsInternal(n),
		Hex: ToHex(n), Expanded: ExpandIPv6(n),
	}
	if b, ok := Special(n); ok {
		info.Special = b.Name
	}
	info.Reverse, _ = ReverseName(n)
	info.EmbeddedV4, _ = EmbeddedIPv4(n)
	return info, nil
}

func (i AddrInfo) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Address:    %s\nVersion:    IPv%d\nExpanded:   %s\nHex:        %s\n", i.Addr, i.Version, i.Expanded, i.Hex)
	fmt.Fprintf(&sb, "Public:     %t\nPrivate:    %t\nLoopback:   %t\nMulticast:  %t\nLink-local: %t\nInternal:   %t\n",
		i.Public, i.Private, i.Loopback, i.Multicast, i.LinkLocal, i.Internal)
	if i.Special != "" {
		fmt.Fprintf(&sb, "Special:    %s\n", i.Special)
	}
	if i.EmbeddedV4.IsValid() {
		fmt.Fprintf(&sb, "Embedded:   %s\n", i.EmbeddedV4)
	}
	fmt.Fprintf(&sb, "PTR:        %s\n", i.Reverse)
	return sb.String()
}

// PrefixInfo is an immutable report about a network.
type PrefixInfo struct {
	Prefix      netip.Prefix
	Version     int
	Bits        int
	Netmask     netip.Addr
	Hostmask    netip.Addr
	Network     netip.Addr
	Broadcast   netip.Addr // invalid for IPv6
	FirstUsable netip.Addr
	LastUsable  netip.Addr
	Size        *big.Int
	UsableHosts *big.Int
}

// InspectPrefix builds a PrefixInfo; host bits are masked.
func InspectPrefix(p netip.Prefix) (PrefixInfo, error) {
	p = NormalizePrefix(p)
	if !p.IsValid() {
		return PrefixInfo{}, ErrInvalidPrefix
	}
	bc, _ := Broadcast(p)
	return PrefixInfo{
		Prefix: p, Version: Family(p.Addr()), Bits: p.Bits(),
		Netmask: Netmask(p), Hostmask: Hostmask(p), Network: First(p), Broadcast: bc,
		FirstUsable: FirstUsable(p), LastUsable: LastUsable(p),
		Size: Size(p), UsableHosts: UsableHosts(p),
	}, nil
}

func (i PrefixInfo) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Network:      %s\nVersion:      IPv%d\nNetmask:      %s\nHostmask:     %s\n", i.Prefix, i.Version, i.Netmask, i.Hostmask)
	if i.Broadcast.IsValid() {
		fmt.Fprintf(&sb, "Broadcast:    %s\n", i.Broadcast)
	}
	fmt.Fprintf(&sb, "First usable: %s\nLast usable:  %s\nSize:         %s\nUsable hosts: %s\n", i.FirstUsable, i.LastUsable, i.Size, i.UsableHosts)
	return sb.String()
}
