package ipx_test

import (
	"fmt"
	"net/http"
	"net/netip"

	"github.com/bakhod1r/ipx"
)

func ExampleAggregate() {
	fmt.Println(ipx.Aggregate([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/25"),
		netip.MustParsePrefix("10.0.0.128/25"),
		netip.MustParsePrefix("10.0.1.0/24"),
	}))
	// Output: [10.0.0.0/23]
}

func ExampleSubtractPrefixes() {
	fmt.Println(ipx.SubtractPrefixes(
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/25")},
	))
	// Output: [10.0.0.128/25]
}

func ExampleSplitN() {
	subs, _ := ipx.SplitN(netip.MustParsePrefix("192.168.1.0/24"), 26, 0)
	fmt.Println(subs)
	// Output: [192.168.1.0/26 192.168.1.64/26 192.168.1.128/26 192.168.1.192/26]
}

func ExamplePlanSubnets() {
	plan, _ := ipx.PlanSubnets(netip.MustParsePrefix("10.0.0.0/24"), []int{26, 25, 27})
	fmt.Println(plan)
	// Output: [10.0.0.128/26 10.0.0.0/25 10.0.0.192/27]
}

func ExampleTable_Lookup() {
	var rt ipx.Table[string]
	rt.Insert(netip.MustParsePrefix("10.0.0.0/8"), "corp")
	rt.Insert(netip.MustParsePrefix("10.10.10.0/24"), "lab")
	p, v, _ := rt.Lookup(netip.MustParseAddr("10.10.10.50"))
	fmt.Println(p, v)
	// Output: 10.10.10.0/24 lab
}

func ExampleRange_Prefixes() {
	r, _ := ipx.ParseRange("10.0.0.5-10.0.0.12")
	fmt.Println(r.Prefixes())
	// Output: [10.0.0.5/32 10.0.0.6/31 10.0.0.8/30 10.0.0.12/32]
}

func ExampleIPSet() {
	a := ipx.NewIPSet(netip.MustParsePrefix("10.0.0.0/24"))
	b := ipx.NewIPSet(netip.MustParsePrefix("10.0.0.128/25"))
	fmt.Println(a.Difference(b))
	fmt.Println(a.Contains(netip.MustParseAddr("::ffff:10.0.0.1")))
	// Output:
	// 10.0.0.0/25
	// true
}

func ExampleIsInternal() {
	for _, s := range []string{"8.8.8.8", "::ffff:169.254.169.254", "64:ff9b::7f00:1"} {
		fmt.Println(s, ipx.IsInternal(netip.MustParseAddr(s)))
	}
	// Output:
	// 8.8.8.8 false
	// ::ffff:169.254.169.254 true
	// 64:ff9b::7f00:1 true
}

func ExampleACL() {
	acl := ipx.NewACL(ipx.LongestPrefix, ipx.Deny)
	acl.Add(ipx.Rule{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Action: ipx.Allow})
	acl.Add(ipx.Rule{Prefix: netip.MustParsePrefix("10.66.0.0/16"), Action: ipx.Deny})
	fmt.Println(acl.Decide(netip.MustParseAddr("10.1.1.1")), acl.Decide(netip.MustParseAddr("10.66.1.1")))
	// Output: allow deny
}

func ExampleAllocator() {
	al, _ := ipx.NewAllocator(netip.MustParsePrefix("10.0.0.0/29"))
	al.Reserve(netip.MustParseAddr("10.0.0.1")) // gateway
	a, _ := al.Allocate()
	fmt.Println(a, al.Available())
	// Output: 10.0.0.2 4
}

func ExampleReverseName() {
	n, _ := ipx.ReverseName(netip.MustParseAddr("8.8.4.4"))
	fmt.Println(n)
	// Output: 4.4.8.8.in-addr.arpa.
}

func ExampleSafeDialer() {
	d := &ipx.SafeDialer{}
	client := &http.Client{Transport: &http.Transport{DialContext: d.DialContext}}
	_, err := client.Get("http://169.254.169.254/latest/meta-data/")
	fmt.Println(err != nil)
	// Output: true
}
