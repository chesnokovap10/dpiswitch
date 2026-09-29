package webui

import "testing"

// the tunnel's server catches port 53: a public server written in the box is
// answered by the server itself -- marked; its own resolver, the endpoint
// itself, DoH and a resolver with its own exit are not
func TestCaughtBy(t *testing.T) {
	ep := "46.8.182.121"
	res := []dnsResult{
		{Server: "84.252.75.74", Kind: "DNS", OK: true, IPs: []string{ep}},
		{Server: "xbox-dns.ru", Kind: "DNS", OK: true, IPs: []string{ep}},
		{Server: "10.8.1.0", Kind: "DNS", OK: true, IPs: []string{ep}},
		{Server: "fd7a:a1c3:8b42:8::", Kind: "DNS", OK: true, IPs: []string{ep}},
		{Server: ep, Kind: "DNS", OK: true, IPs: []string{ep}},
		{Server: "https://xbox-dns.ru/dns-query", Kind: "DoH", OK: true, IPs: []string{ep}},
		{Server: "1.1.1.1", Kind: "DNS", OK: true, IPs: []string{"172.69.50.55"}},
		{Server: "9.9.9.9", Kind: "DNS", OK: false},
	}
	caughtBy(ep, res)
	want := []bool{true, true, false, false, false, false, false, false}
	for i, r := range res {
		if r.Caught != want[i] {
			t.Errorf("%s: caught %v, want %v", r.Server, r.Caught, want[i])
		}
	}
	// an endpoint given by name: nothing to compare with
	res = []dnsResult{{Server: "84.252.75.74", Kind: "DNS", OK: true, IPs: []string{ep}}}
	caughtBy("vpn.example.com", res)
	if res[0].Caught {
		t.Error("marked with an endpoint given by name")
	}
}
