package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	cases := []struct {
		args []string
		want string
		code int
	}{
		{[]string{"parse", "::ffff:1.2.3.4"}, "1.2.3.4\n", 0},
		{[]string{"info", "10.0.0.1"}, "Private:    true", 0},
		{[]string{"cidr", "192.168.1.9/24"}, "Broadcast:    192.168.1.255", 0},
		{[]string{"contains", "192.168.1.0/24", "192.168.1.50"}, "true\n", 0},
		{[]string{"contains", "192.168.1.0/24", "10.0.0.1"}, "false\n", 1},
		{[]string{"split", "192.168.1.0/24", "26"}, "192.168.1.192/26\n", 0},
		{[]string{"aggregate", "10.0.0.0/25", "10.0.0.128/25"}, "10.0.0.0/24\n", 0},
		{[]string{"diff", "10.0.0.0/24", "10.0.0.0/25"}, "10.0.0.128/25\n", 0},
		{[]string{"range", "10.0.0.0-10.0.0.3"}, "10.0.0.0/30\n", 0},
		{[]string{"reverse", "8.8.8.8"}, "8.8.8.8.in-addr.arpa.\n", 0},
		{[]string{"parse", "nope"}, "invalid IP address", 2},
		{[]string{"bogus"}, "usage", 2},
		{nil, "usage", 2},
	}
	for _, c := range cases {
		var out bytes.Buffer
		code := run(c.args, &out)
		if code != c.code || !strings.Contains(out.String(), c.want) {
			t.Errorf("%v: code %d out %q", c.args, code, out.String())
		}
	}
}

func TestRunV3(t *testing.T) {
	cases := []struct {
		args []string
		want string
		code int
	}{
		{[]string{"plan", "10.0.0.0/24", "26", "25", "27"}, "10.0.0.128/26\n10.0.0.0/25\n10.0.0.192/27\n", 0},
		{[]string{"plan", "10.0.0.0/24", "25", "25", "25"}, "exhausted", 2},
		{[]string{"plan", "10.0.0.0/24", "hosts:50", "hosts:100"}, "10.0.0.128/26\n10.0.0.0/25\n", 0},
		{[]string{"alloc", "10.0.0.0/29", "3"}, "10.0.0.1\n10.0.0.2\n10.0.0.3\n", 0},
		{[]string{"alloc", "10.0.0.0/29", "3", "--reserve", "10.0.0.1"}, "10.0.0.2\n10.0.0.3\n10.0.0.4\n", 0},
		{[]string{"alloc", "10.0.0.0/30", "3"}, "exhausted", 2},
		{[]string{"--json", "split", "10.0.0.0/24", "25"}, `["10.0.0.0/25","10.0.0.128/25"]`, 0},
		{[]string{"--json", "contains", "10.0.0.0/24", "10.0.0.1"}, "true\n", 0},
		{[]string{"--json", "info", "10.0.0.1"}, `"Private":true`, 0},
		{[]string{"--json", "cidr", "10.0.0.0/24"}, `"UsableHosts":254`, 0},
		{[]string{"--json", "reverse", "8.8.8.8"}, `"8.8.8.8.in-addr.arpa."`, 0},
		{[]string{"--json", "parse", "bad"}, `{"error":`, 2},
	}
	for _, c := range cases {
		var out bytes.Buffer
		code := run(c.args, &out)
		if code != c.code || !strings.Contains(out.String(), c.want) {
			t.Errorf("%v: code %d out %q", c.args, code, out.String())
		}
	}
}
