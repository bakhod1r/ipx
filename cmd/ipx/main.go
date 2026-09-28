// Command ipx is a CLI for the ipx library.
package main

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"

	"github.com/bakhod1r/ipx"
)

const usage = `usage: ipx <command> [args]
  parse     <ip>                 normalize an address
  info      <ip>                 classify an address
  cidr      <prefix>             subnet details
  contains  <prefix|range> <ip>  exit 0 if contained, 1 if not
  split     <prefix> <bits>      list subnets (max 4096)
  aggregate <net>...             minimal CIDR cover
  diff      <net> <net>...       first minus the rest
  range     <a-b>                range as CIDRs
  reverse   <ip>                 PTR name
`

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

// run executes a command; exit codes: 0 ok, 1 negative answer, 2 error.
func run(args []string, w io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(w, usage)
		return 2
	}
	code, err := dispatch(args[0], args[1:], w)
	if err != nil {
		fmt.Fprintln(w, "error:", err)
		return 2
	}
	return code
}

func need(args []string, n int) error {
	if len(args) < n {
		return fmt.Errorf("need %d argument(s)\n%s", n, usage)
	}
	return nil
}

func dispatch(cmd string, args []string, w io.Writer) (int, error) {
	switch cmd {
	case "parse", "info", "reverse":
		if err := need(args, 1); err != nil {
			return 2, err
		}
		a, err := ipx.ParseAddr(args[0])
		if err != nil {
			return 2, err
		}
		switch cmd {
		case "parse":
			fmt.Fprintln(w, ipx.Normalize(a))
		case "info":
			i, _ := ipx.InspectAddr(a)
			fmt.Fprint(w, i)
		default:
			n, _ := ipx.ReverseName(a)
			fmt.Fprintln(w, n)
		}
	case "cidr":
		if err := need(args, 1); err != nil {
			return 2, err
		}
		p, err := ipx.ParsePrefix(args[0])
		if err != nil {
			return 2, err
		}
		i, _ := ipx.InspectPrefix(p)
		fmt.Fprint(w, i)
	case "contains":
		if err := need(args, 2); err != nil {
			return 2, err
		}
		r, err := ipx.ParseRange(args[0])
		if err != nil {
			return 2, err
		}
		a, err := ipx.ParseAddr(args[1])
		if err != nil {
			return 2, err
		}
		ok := r.Contains(a)
		fmt.Fprintln(w, ok)
		if !ok {
			return 1, nil
		}
	case "split":
		if err := need(args, 2); err != nil {
			return 2, err
		}
		p, err := ipx.ParsePrefix(args[0])
		if err != nil {
			return 2, err
		}
		bits, err := strconv.Atoi(args[1])
		if err != nil {
			return 2, err
		}
		subs, err := ipx.SplitN(p, bits, 4096)
		if err != nil {
			return 2, err
		}
		printPrefixes(w, subs)
	case "aggregate", "diff":
		if err := need(args, 1); err != nil {
			return 2, err
		}
		sets := make([]*ipx.IPSet, len(args))
		for i, s := range args {
			r, err := ipx.ParseRange(s)
			if err != nil {
				return 2, err
			}
			sets[i] = ipx.NewIPSet(r)
		}
		acc := sets[0]
		for _, s := range sets[1:] {
			if cmd == "aggregate" {
				acc = acc.Union(s)
			} else {
				acc = acc.Difference(s)
			}
		}
		printPrefixes(w, acc.Prefixes())
	case "range":
		if err := need(args, 1); err != nil {
			return 2, err
		}
		r, err := ipx.ParseRange(args[0])
		if err != nil {
			return 2, err
		}
		printPrefixes(w, r.Prefixes())
	default:
		return 2, fmt.Errorf("unknown command %q\n%s", cmd, usage)
	}
	return 0, nil
}

func printPrefixes(w io.Writer, ps []netip.Prefix) {
	for _, p := range ps {
		fmt.Fprintln(w, p)
	}
}
