package ctl

import "testing"

func TestPickGatewaySkipsTUN(t *testing.T) {
	// route output after a Wi-Fi reconnect: the TUN line comes first
	out := "          0.0.0.0          0.0.0.0       198.18.0.2       198.18.0.1      0\r\n" +
		"          0.0.0.0          0.0.0.0     192.168.31.1   192.168.31.250     30\r\n"
	if got := pickGateway(out); got != "192.168.31.1" {
		t.Fatalf("picked %q, want 192.168.31.1", got)
	}
	// two physical networks: the lower metric wins
	out += "          0.0.0.0          0.0.0.0     10.0.0.1       10.0.0.5     25\r\n"
	if got := pickGateway(out); got != "10.0.0.1" {
		t.Fatalf("picked %q, want 10.0.0.1", got)
	}
	if got := pickGateway("          0.0.0.0          0.0.0.0       198.18.0.2       198.18.0.1      0\r\n"); got != "" {
		t.Fatalf("only TUN -- there is no gateway, yet picked %q", got)
	}
}
