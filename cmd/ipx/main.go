// Command ipx is a CLI for the ipx library.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/bakhod1r/ipx"
)

const usage = `usage: ipx [--json] <command> [args]
  parse     <ip>                        normalize an address
  info      <ip>                        classify an address
  cidr      <prefix>                    subnet details
  contains  <prefix|range> <ip>         exit 0 if contained, 1 if not
  split     <prefix> <bits>             list subnets (max 4096)
  aggregate <net>...                    minimal CIDR cover
  diff      <net> <net>...              first minus the rest
  range     <a-b>                       range as CIDRs
  reverse   <ip>                        PTR name
  plan      <prefix> <len|hosts:N>...   VLSM plan, output in request order
  alloc     <prefix> <n> [--reserve ip]...  first n free host addresses
`

var exit = os.Exit

func main() { exit(run(os.Args[1:], os.Stdout)) }

// run executes a command; exit codes: 0 ok, 1 negative answer, 2 error.
func run(args []string, w io.Writer) int {
	asJSON := len(args) > 0 && args[0] == "--json"
	if asJSON {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprint(w, usage)
		return 2
	}
	v, code, err := dispatch(args[0], args[1:])
	if err != nil {
		if asJSON {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		} else {
			fmt.Fprintln(w, "error:", err)
		}
		return 2
	}
	if asJSON {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
	} else {
		printText(w, v)
	}
	return code
}

func printText(w io.Writer, v any) {
	switch x := v.(type) {
	case []netip.Prefix:
		for _, p := range x {
			fmt.Fprintln(w, p)
		}
	case []netip.Addr:
		for _, a := range x {
			fmt.Fprintln(w, a)
		}
	default:
		fmt.Fprint(w, x)
		if s, ok := x.(fmt.Stringer); !ok || !strings.HasSuffix(s.String(), "\n") {
			fmt.Fprintln(w)
		}
	}
}

func need(args []string, n int) error {
	if len(args) < n {
		return fmt.Errorf("need %d argument(s)\n%s", n, usage)
	}
	return nil
}

func dispatch(cmd string, args []string) (any, int, error) {
	switch cmd {
	case "parse", "info", "reverse":
		if err := need(args, 1); err != nil {
			return nil, 2, err
		}
		a, err := ipx.ParseAddr(args[0])
		if err != nil {
			return nil, 2, err
		}
		switch cmd {
		case "parse":
			return ipx.Normalize(a), 0, nil
		case "info":
			i, _ := ipx.InspectAddr(a)
			return i, 0, nil
		}
		n, _ := ipx.ReverseName(a)
		return n, 0, nil
	case "cidr":
		if err := need(args, 1); err != nil {
			return nil, 2, err
		}
		p, err := ipx.ParsePrefix(args[0])
		if err != nil {
			return nil, 2, err
		}
		i, _ := ipx.InspectPrefix(p)
		return i, 0, nil
	case "contains":
		if err := need(args, 2); err != nil {
			return nil, 2, err
		}
		r, err := ipx.ParseRange(args[0])
		if err != nil {
			return nil, 2, err
		}
		a, err := ipx.ParseAddr(args[1])
		if err != nil {
			return nil, 2, err
		}
		if r.Contains(a) {
			return true, 0, nil
		}
		return false, 1, nil
	case "split":
		if err := need(args, 2); err != nil {
			return nil, 2, err
		}
		p, err := ipx.ParsePrefix(args[0])
		if err != nil {
			return nil, 2, err
		}
		bits, err := strconv.Atoi(args[1])
		if err != nil {
			return nil, 2, err
		}
		subs, err := ipx.SplitN(p, bits, 4096)
		return subs, 0, err
	case "aggregate", "diff":
		if err := need(args, 1); err != nil {
			return nil, 2, err
		}
		var acc *ipx.IPSet
		for i, s := range args {
			r, err := ipx.ParseRange(s)
			if err != nil {
				return nil, 2, err
			}
			set := ipx.NewIPSet(r)
			switch {
			case i == 0:
				acc = set
			case cmd == "aggregate":
				acc = acc.Union(set)
			default:
				acc = acc.Difference(set)
			}
		}
		return acc.Prefixes(), 0, nil
	case "range":
		if err := need(args, 1); err != nil {
			return nil, 2, err
		}
		r, err := ipx.ParseRange(args[0])
		if err != nil {
			return nil, 2, err
		}
		return r.Prefixes(), 0, nil
	case "plan":
		return plan(args)
	case "alloc":
		return alloc(args)
	}
	return nil, 2, fmt.Errorf("unknown command %q\n%s", cmd, usage)
}

// plan: each request is a prefix length ("26") or a host count ("hosts:50").
func plan(args []string) (any, int, error) {
	if err := need(args, 2); err != nil {
		return nil, 2, err
	}
	p, err := ipx.ParsePrefix(args[0])
	if err != nil {
		return nil, 2, err
	}
	lengths := make([]int, 0, len(args)-1)
	for _, s := range args[1:] {
		if h, ok := strings.CutPrefix(s, "hosts:"); ok {
			n, err := strconv.ParseUint(h, 10, 64)
			if err != nil {
				return nil, 2, fmt.Errorf("bad host count %q", s)
			}
			l, err := ipx.PrefixLenForHosts(n, p.Addr().Is6())
			if err != nil {
				return nil, 2, err
			}
			lengths = append(lengths, l)
			continue
		}
		l, err := strconv.Atoi(s)
		if err != nil {
			return nil, 2, fmt.Errorf("bad prefix length %q", s)
		}
		lengths = append(lengths, l)
	}
	out, err := ipx.PlanSubnets(p, lengths)
	return out, 0, err
}

func alloc(args []string) (any, int, error) {
	if err := need(args, 2); err != nil {
		return nil, 2, err
	}
	p, err := ipx.ParsePrefix(args[0])
	if err != nil {
		return nil, 2, err
	}
	n, err := strconv.Atoi(args[1])
	if err != nil || n < 1 || n > 65536 {
		return nil, 2, fmt.Errorf("count must be 1-65536, got %q", args[1])
	}
	al, _ := ipx.NewAllocator(p) // only fails for an invalid prefix, parsed above
	rest := args[2:]
	for len(rest) > 0 {
		if rest[0] != "--reserve" || len(rest) < 2 {
			return nil, 2, fmt.Errorf("unexpected argument %q", rest[0])
		}
		a, err := ipx.ParseAddr(rest[1])
		if err != nil {
			return nil, 2, err
		}
		if err := al.Reserve(a); err != nil {
			return nil, 2, err
		}
		rest = rest[2:]
	}
	out, err := al.AllocateN(n)
	return out, 0, err
}
