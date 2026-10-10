package udpguard

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tailscale/wf"
)

// What the guard's rules rest on, one formulation at a time against the real
// engine: each in a session of its own, with datagrams sent out of the
// adapter by its address -- connected and not -- and the engine's record of
// what it dropped. Run like TestLive. Found so on 06.10.2026, Windows 10 LTSC
// 21H2:
//
//   - the interface type is a condition of the connect layer, and several
//     conditions on it are alternatives, as are the types of an adapter and
//     an adapter's LUID: the block by type holds where the adapter is Wi-Fi
//     or Ethernet;
//   - the weights are the order the rules are looked at in, whichever was put
//     in first: a permit above the block lets its packets through, one below
//     it does not.
func TestLiveLab(t *testing.T) {
	gateLive(t)
	if Present() {
		t.Skip("the service's guard is in the engine: the lab's rules take its keys, and stand alone. Switch the guard off in the settings to run it")
	}
	up := findUplink(t)
	t.Logf("adapter %q: IPv4 %v", up.name, up.v4)
	target := netip.MustParseAddr("192.0.2.1")
	lan := netip.MustParseAddr("10.255.255.1")

	pfx := func(s string) *wf.Match {
		return &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix(s)}
	}
	itype := func(n uint32) *wf.Match {
		return &wf.Match{Field: wf.FieldInterfaceType, Op: wf.MatchTypeEqual, Value: n}
	}
	udp := &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP}

	spec, err := wf.New(&wf.Options{Name: "lab: the record", Dynamic: true})
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Close()

	type rule struct {
		weight uint64
		action wf.Action
		conds  []*wf.Match
	}
	variants := []struct {
		name  string
		rules []rule // added in this order
		// which of the probes are expected dropped: the public one, the private one
		public, private bool
	}{
		{"block interface type 71", []rule{{0x100, wf.ActionBlock, []*wf.Match{itype(71)}}}, true, true},
		{"block interface types 6 or 71", []rule{{0x100, wf.ActionBlock, []*wf.Match{itype(6), itype(71)}}}, true, true},
		{"block types 6, 71, 243, 244", []rule{{0x100, wf.ActionBlock, []*wf.Match{itype(6), itype(71), itype(243), itype(244)}}}, true, true},
		{"block type 6 alone: Wi-Fi is not Ethernet", []rule{{0x100, wf.ActionBlock, []*wf.Match{itype(6)}}}, false, false},
		{"block, then permit 10/8 above it", []rule{
			{0x100, wf.ActionBlock, []*wf.Match{itype(71)}},
			{0x300, wf.ActionPermit, []*wf.Match{pfx("10.0.0.0/8")}},
		}, true, false},
		{"permit 10/8 below the block, put first", []rule{
			{0x100, wf.ActionPermit, []*wf.Match{pfx("10.0.0.0/8")}},
			{0x300, wf.ActionBlock, []*wf.Match{itype(71)}},
		}, true, true},
		{"permit 10/8 above the block, put last", []rule{
			{0x100, wf.ActionBlock, []*wf.Match{itype(71)}},
			{0x200, wf.ActionPermit, []*wf.Match{pfx("10.0.0.0/8")}},
		}, true, false},
	}
	for _, v := range variants {
		s, err := wf.New(&wf.Options{Name: "lab", Dynamic: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.AddProvider(&wf.Provider{ID: providerKey, Name: "lab"}); err != nil {
			t.Fatal(err)
		}
		if err := s.AddSublayer(&wf.Sublayer{ID: sublayerKey, Name: "lab", Provider: providerKey, Weight: 0xffff}); err != nil {
			t.Fatal(err)
		}
		failed := false
		for i, r := range v.rules {
			err := s.AddRule(&wf.Rule{ID: ruleKey(i), Name: "lab rule", Layer: wf.LayerALEAuthConnectV4,
				Sublayer: sublayerKey, Provider: providerKey, Weight: r.weight, Action: r.action,
				Conditions: append([]*wf.Match{udp}, r.conds...)})
			if err != nil {
				t.Errorf("%s: AddRule %d: %v", v.name, i, err)
				failed = true
				break
			}
		}
		if failed {
			s.Close()
			continue
		}
		since := time.Now().Add(-time.Second)
		pub, e1 := send(up.v4, target, 9, "")
		pubU, e2 := sendUnconnected(up.v4, target, 9)
		priv, e3 := send(up.v4, lan, 9, "")
		time.Sleep(500 * time.Millisecond)
		got := func(f flow) bool { return sessionSawDrop(spec, f.local, f.remote, since) }
		gp, gu, gl := got(pub), got(pubU), got(priv)
		t.Logf("%-46s public: %-8v (connected) %-8v (not) private: %-8v   sent %s/%s/%s",
			v.name, gp, gu, gl, describe(e1), describe(e2), describe(e3))
		if gp != v.public || gu != v.public || gl != v.private {
			t.Errorf("%s: public dropped %v/%v, private dropped %v; want %v and %v", v.name, gp, gu, gl, v.public, v.private)
		}
		s.Close()
	}
}
