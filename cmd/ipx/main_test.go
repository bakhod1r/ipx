package main

import (
	"bytes"
	"io"
	"os"
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

func TestRunErrors(t *testing.T) {
	bad := [][]string{
		{"parse"}, {"cidr"}, {"cidr", "x"}, {"contains", "x"}, {"contains", "x", "1.1.1.1"},
		{"contains", "10.0.0.0/8", "x"}, {"split", "x"}, {"split", "x", "1"}, {"split", "10.0.0.0/8", "x"},
		{"aggregate"}, {"aggregate", "x"}, {"range"}, {"range", "x"},
		{"plan", "x"}, {"plan", "x", "24"}, {"plan", "10.0.0.0/8", "hosts:x"},
		{"plan", "10.0.0.0/8", "hosts:99999999999"}, {"plan", "10.0.0.0/8", "x"},
		{"alloc", "x"}, {"alloc", "x", "1"}, {"alloc", "10.0.0.0/8", "0"}, {"alloc", "10.0.0.0/8", "1", "--oops"},
		{"alloc", "10.0.0.0/8", "1", "--reserve", "x"}, {"alloc", "10.0.0.0/8", "1", "--reserve", "11.0.0.1"},
	}
	for _, args := range bad {
		var out bytes.Buffer
		if code := run(args, &out); code != 2 || !strings.Contains(out.String(), "error") {
			t.Errorf("%v: code %d out %q", args, code, out.String())
		}
	}
	// hosts:N on an IPv6 parent uses IPv6 sizing.
	var out bytes.Buffer
	if run([]string{"plan", "2001:db8::/64", "hosts:256"}, &out) != 0 || out.String() != "2001:db8::/120\n" {
		t.Error(out.String())
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestJSONWriteError(t *testing.T) {
	if code := run([]string{"--json", "parse", "1.1.1.1"}, failWriter{}); code != 2 {
		t.Error(code)
	}
}

func TestMain_(t *testing.T) {
	var got int
	exit = func(c int) { got = c }
	defer func() { exit = os.Exit }()
	old := os.Args
	defer func() { os.Args = old }()
	os.Args = []string{"ipx", "parse", "1.1.1.1"}
	main()
	if got != 0 {
		t.Error(got)
	}
}
