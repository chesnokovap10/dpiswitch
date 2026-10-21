package ctl

import (
	"slices"
	"testing"
)

// The core's lines as it writes them: a connection each, read as the
// connection table would show it.
func TestParseConnLine(t *testing.T) {
	for _, tc := range []struct {
		line                     string
		network, host, ip, port  string
		src, proc, rule, payload string
		chains                   []string
	}{
		{`time="2026-10-21T18:50:05.566150300+03:00" level=info msg="[TCP] [fdfe:dcba:9876::1]:58310(curl.exe) --> www.linkedin.com:443 match Match using tunnel-rest[awg1]"`,
			"tcp", "www.linkedin.com", "", "443", "fdfe:dcba:9876::1", "curl.exe", "Match", "", []string{"awg1", "tunnel-rest"}},
		{`time="2026-10-21T18:50:05.492746500+03:00" level=info msg="[TCP] [fdfe:dcba:9876::1]:58286(curl.exe) --> dzen.ru:443 match AND(((DomainRegex,.+) && (RuleSet,inherit-ip))) using direct-split"`,
			"tcp", "dzen.ru", "", "443", "fdfe:dcba:9876::1", "curl.exe", "AND", "((DomainRegex,.+) && (RuleSet,inherit-ip))", []string{"direct-split"}},
		{`time="2026-10-21T18:37:28.249262800+03:00" level=info msg="[TCP] 198.18.0.1:55723(ssh.exe) --> 84.252.75.74:22 match IPCIDR(84.252.75.74/32) using DIRECT"`,
			"tcp", "", "84.252.75.74", "22", "198.18.0.1", "ssh.exe", "IPCIDR", "84.252.75.74/32", []string{"DIRECT"}},
		{`time="2026-10-21T18:50:05.0+03:00" level=info msg="[UDP] 198.18.0.1:61000(Code - Insiders.exe) --> rr1---sn-x.googlevideo.com:443 match RuleSet(family-direct) using direct-split"`,
			"udp", "rr1---sn-x.googlevideo.com", "", "443", "198.18.0.1", "Code - Insiders.exe", "RuleSet", "family-direct", []string{"direct-split"}},
		{`time="2026-10-21T18:28:46.420964900+03:00" level=info msg="[TCP] 127.0.0.1:53699 --> r1---sn-c5niuxaxjvh-045l.googlevideo.com:443 using awg1"`,
			"tcp", "r1---sn-c5niuxaxjvh-045l.googlevideo.com", "", "443", "127.0.0.1", "", "", "", []string{"awg1"}},
	} {
		c, ok := parseConnLine(tc.line)
		if !ok {
			t.Errorf("not read: %s", tc.line)
			continue
		}
		m := c.Metadata
		if m.Network != tc.network || m.Host != tc.host || m.DestinationIP != tc.ip || m.DestinationPort != tc.port ||
			m.SourceIP != tc.src || m.Process != tc.proc || c.Rule != tc.rule || c.RulePayload != tc.payload || !slices.Equal(c.Chains, tc.chains) {
			t.Errorf("%s\n read %+v", tc.line, c)
		}
	}
	for _, line := range []string{
		`time="2026-10-21T18:55:54.783293800+03:00" level=info msg="[UDP] mihomo --> 10.8.1.0:53 doesn't match any rule using awg2"`,
		`time="2026-10-21T18:51:04.820838200+03:00" level=warning msg="[TCP] dial direct-split (match RuleSet/inherit) 198.18.0.1:58420(svchost.exe) --> pti.store.microsoft.com:443 error: dns resolve failed: couldn't find ip"`,
		`time="2026-10-21T18:47:28.713662200+03:00" level=info msg="Start initial provider family-direct"`,
	} {
		if c, ok := parseConnLine(line); ok {
			t.Errorf("read %+v from %s", c, line)
		}
	}
}

// A connection shorter than the watcher's look is taken from the core's
// line: a candidate at once, and the fast lane told.
func TestCoreLogLineFeedsWatcher(t *testing.T) {
	s := newScenario(t)
	s.w.wake = make(chan struct{}, 1)
	feed.Store(&logFeed{w: s.w, cfg: s.cfg})
	t.Cleanup(func() { feed.Store(nil) })
	CoreLogLine(`time="2026-10-21T18:50:05.566150300+03:00" level=info msg="[TCP] [fdfe:dcba:9876::1]:58310(curl.exe) --> meduza.io:443 match Match using tunnel-rest[awg1]"`)
	CoreLogLine(`time="2026-10-21T18:50:05.6+03:00" level=info msg="[TCP] 127.0.0.1:53699 --> probe.example.org:443 using awg1"`)
	select {
	case <-s.w.wake:
	default:
		t.Fatal("the fast lane not told")
	}
	doms, ports := s.w.takeFresh()
	if !slices.Equal(doms, []string{"meduza.io"}) || len(ports["meduza.io"]) != 1 || ports["meduza.io"][0] != (endpoint{port: 443}) {
		t.Fatalf("fresh %v %v", doms, ports)
	}
}
