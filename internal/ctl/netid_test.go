package ctl

import "testing"

func TestPickGatewaySkipsTUN(t *testing.T) {
	// вывод route после переподключения Wi-Fi: строка TUN идёт первой
	out := "          0.0.0.0          0.0.0.0       198.18.0.2       198.18.0.1      0\r\n" +
		"          0.0.0.0          0.0.0.0     192.168.31.1   192.168.31.250     30\r\n"
	if got := pickGateway(out); got != "192.168.31.1" {
		t.Fatalf("выбран %q, ждал 192.168.31.1", got)
	}
	// две физические сети: побеждает меньшая метрика
	out += "          0.0.0.0          0.0.0.0     10.0.0.1       10.0.0.5     25\r\n"
	if got := pickGateway(out); got != "10.0.0.1" {
		t.Fatalf("выбран %q, ждал 10.0.0.1", got)
	}
	if got := pickGateway("          0.0.0.0          0.0.0.0       198.18.0.2       198.18.0.1      0\r\n"); got != "" {
		t.Fatalf("только TUN -- шлюза нет, а выбран %q", got)
	}
}
