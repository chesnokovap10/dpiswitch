package probe

import "testing"

func TestParseResolverIPv6(t *testing.T) {
	cases := map[string][2]string{ // input -> {host, scheme}
		"fd7a:a1c3:8b42::":                 {"fd7a:a1c3:8b42::", "udp"},
		"[fd7a:a1c3:8b42::]:53":            {"fd7a:a1c3:8b42::", "udp"},
		"tls://2606:4700:4700::1111":       {"2606:4700:4700::1111", "tls"},
		"https://2606:4700:4700::1111/dns": {"2606:4700:4700::1111", "https"},
		"10.8.1.0":                         {"10.8.1.0", "udp"},
		"https://77.88.8.8/dns-query":      {"77.88.8.8", "https"},
	}
	for in, want := range cases {
		r, err := ParseResolver(in)
		if err != nil || r.Host != want[0] || r.Scheme != want[1] {
			t.Errorf("%q: host=%q scheme=%q err=%v, want %v", in, r.Host, r.Scheme, err, want)
		}
	}
	if r, _ := ParseResolver("https://2606:4700:4700::1111/dns"); r.Path != "/dns" {
		t.Errorf("path lost: %q", r.Path)
	}
}
