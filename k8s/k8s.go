// Package k8s provides Kubernetes cluster-network helpers built on ipx:
// overlap validation for pod/service/node CIDRs, node podCIDR carving and
// well-known service IPs. Standard library only; no client-go dependency.
package k8s

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"

	"github.com/bakhod1r/ipx"
)

var (
	ErrOverlap             = errors.New("k8s: cluster networks overlap")
	ErrServiceCIDRTooLarge = errors.New("k8s: service CIDR larger than 20 host bits")
	ErrOutOfRange          = errors.New("k8s: index outside CIDR")
)

// maxServiceHostBits mirrors kube-apiserver's limit (/12 for IPv4, /108 for IPv6).
const maxServiceHostBits = 20

// Networks describes a cluster's address plan. Dual-stack clusters list
// one prefix per family.
type Networks struct {
	Pods     []netip.Prefix // --cluster-cidr
	Services []netip.Prefix // --service-cluster-ip-range
	Nodes    []netip.Prefix // node/host networks (VPC subnets)
}

// Validate checks every prefix is valid, service ranges are within the
// apiserver limit, and no two roles overlap. All problems are joined.
func (n Networks) Validate() error {
	type tagged struct {
		role string
		p    netip.Prefix
	}
	var (
		errs []error
		all  []tagged
	)
	for _, g := range []struct {
		role string
		ps   []netip.Prefix
	}{{"pods", n.Pods}, {"services", n.Services}, {"nodes", n.Nodes}} {
		for _, p := range g.ps {
			if !p.IsValid() {
				errs = append(errs, fmt.Errorf("%w: %s entry", ipx.ErrInvalidPrefix, g.role))
				continue
			}
			p = ipx.NormalizePrefix(p)
			if g.role == "services" && p.Addr().BitLen()-p.Bits() > maxServiceHostBits {
				errs = append(errs, fmt.Errorf("%w: %s", ErrServiceCIDRTooLarge, p))
			}
			all = append(all, tagged{g.role, p})
		}
	}
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			a, b := all[i], all[j]
			if a.role != b.role && a.p.Overlaps(b.p) {
				errs = append(errs, fmt.Errorf("%w: %s %s and %s %s", ErrOverlap, a.role, a.p, b.role, b.p))
			}
		}
	}
	return errors.Join(errs...)
}

// ServiceIP returns the index-th address of a service CIDR. Index 0 (network)
// and, for IPv4, the broadcast address are rejected.
func ServiceIP(svc netip.Prefix, index int64) (netip.Addr, error) {
	svc = ipx.NormalizePrefix(svc)
	if !svc.IsValid() {
		return netip.Addr{}, ipx.ErrInvalidPrefix
	}
	if index < 1 || big.NewInt(index).Cmp(ipx.UsableHosts(svc)) > 0 {
		return netip.Addr{}, fmt.Errorf("%w: %d in %s", ErrOutOfRange, index, svc)
	}
	return ipx.Add(ipx.First(svc), index)
}

// APIServerIP is the "kubernetes" Service ClusterIP: the first address.
func APIServerIP(svc netip.Prefix) (netip.Addr, error) { return ServiceIP(svc, 1) }

// DNSServiceIP is kubeadm's default cluster DNS ClusterIP: the tenth address.
func DNSServiceIP(svc netip.Prefix) (netip.Addr, error) { return ServiceIP(svc, 10) }

// MaxNodes returns how many nodes a cluster CIDR supports with the given
// --node-cidr-mask-size.
func MaxNodes(cluster netip.Prefix, nodeMaskSize int) (*big.Int, error) {
	return ipx.SubnetCount(cluster, nodeMaskSize)
}

// NodeCIDRs returns the first count podCIDRs of size nodeMaskSize, in the
// order the node IPAM controller hands them out.
func NodeCIDRs(cluster netip.Prefix, nodeMaskSize, count int) ([]netip.Prefix, error) {
	max, err := MaxNodes(cluster, nodeMaskSize)
	if err != nil {
		return nil, err
	}
	if count < 0 || big.NewInt(int64(count)).Cmp(max) > 0 {
		return nil, fmt.Errorf("%w: %d nodes, %s fit", ipx.ErrExhausted, count, max)
	}
	return ipx.SplitN(cluster, nodeMaskSize, count)
}

// MaxPodsPerNode returns usable pod IPs in an IPv4 podCIDR of the given
// mask size (network and broadcast excluded).
func MaxPodsPerNode(nodeMaskSize int) (int64, error) {
	if nodeMaskSize < 0 || nodeMaskSize > 32 {
		return 0, ipx.ErrInvalidPrefix
	}
	return ipx.UsableHosts(netip.PrefixFrom(netip.IPv4Unspecified(), nodeMaskSize)).Int64(), nil
}
