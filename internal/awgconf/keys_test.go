package awgconf

import (
	"strings"
	"testing"
)

const goodKey = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// A key that is not base64 of 32 bytes is refused, the preshared one only
// when there is one
func TestCheckKeys(t *testing.T) {
	conf := func(priv, pub, psk string) *Conf {
		t.Helper()
		text := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.8.1.3/32\n[Peer]\nPublicKey = " + pub + "\nEndpoint = 198.51.100.7:51820\n"
		if psk != "" {
			text += "PresharedKey = " + psk + "\n"
		}
		c, err := Parse(text)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if err := conf(goodKey, goodKey, "").CheckKeys(); err != nil {
		t.Errorf("good keys: %v", err)
	}
	if err := conf(goodKey, goodKey, goodKey).CheckKeys(); err != nil {
		t.Errorf("good keys with a preshared one: %v", err)
	}
	for _, c := range []struct{ priv, pub, psk, want string }{
		{"k", goodKey, "", "PrivateKey"},
		{goodKey, "cA==", "", "PublicKey"},
		{goodKey, goodKey + "x", "", "PublicKey"},
		{goodKey, goodKey, "AAAA", "PresharedKey"},
	} {
		if err := conf(c.priv, c.pub, c.psk).CheckKeys(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

// AWG 3.x writes PersistentKeepalive as a range too: taken, and the core
// gets its low end -- it takes a number only
func TestKeepaliveRange(t *testing.T) {
	for v, want := range map[string]int{"25": 25, "25-35": 25, " 25 - 35 ": 25, "0": 0} {
		if got, ok := keepalive(v); !ok || got != want {
			t.Errorf("%q: %d %v, want %d", v, got, ok, want)
		}
	}
	for _, v := range []string{"x", "-5", "35-25", "25-", "25-x"} {
		if _, ok := keepalive(v); ok {
			t.Errorf("%q taken", v)
		}
	}
	c, err := Parse("[Interface]\nPrivateKey = " + goodKey + "\nAddress = 10.8.1.3/32\n[Peer]\nPublicKey = " + goodKey +
		"\nEndpoint = 198.51.100.7:51820\nPersistentKeepalive = 25-35\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.check(); err != nil {
		t.Fatalf("a range refused: %v", err)
	}
	out, err := c.Render()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "    persistent-keepalive: 25\n") {
		t.Error("the core got no number for the range")
	}
}
