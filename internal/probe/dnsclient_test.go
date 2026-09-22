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

// A response carries both an A and an AAAA record for the same name; each
// query type must pick out its own and ignore the other. Before this the
// parser only knew type A, so an IPv6-only host looked like "no records".
func TestParseAnswerByType(t *testing.T) {
	name := "ipv6.example.com"
	for _, tc := range []struct {
		qtype uint16
		want  string
	}{
		{typeA, "192.0.2.7"},
		{typeAAAA, "2001:db8::7"},
	} {
		q, id := buildQuery(name, tc.qtype)
		resp := answerWith(q, id)
		got, err := parseAnswer(resp, id, tc.qtype)
		if err != nil {
			t.Fatalf("type %d: %v", tc.qtype, err)
		}
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("type %d: got %v, want [%s]", tc.qtype, got, tc.want)
		}
	}
}

// answerWith echoes the question and appends one A and one AAAA record.
func answerWith(q []byte, id uint16) []byte {
	m := make([]byte, len(q))
	copy(m, q)
	m[2] = 0x81 // response, recursion desired
	m[3] = 0x80 // recursion available, rcode 0
	m[7] = 2    // two answers
	rr := func(typ uint16, data []byte) {
		m = append(m, 0xc0, 0x0c) // pointer to the name in the question
		m = append(m, byte(typ>>8), byte(typ), 0, 1, 0, 0, 0, 60,
			byte(len(data)>>8), byte(len(data)))
		m = append(m, data...)
	}
	rr(typeA, []byte{192, 0, 2, 7})
	v6 := make([]byte, 16)
	v6[0], v6[1], v6[15] = 0x20, 0x01, 0x07
	v6[2], v6[3] = 0x0d, 0xb8
	rr(typeAAAA, v6)
	return m
}
