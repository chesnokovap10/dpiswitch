package ctl

import (
	"context"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dpiswitch/internal/probe"
)

// A name first seen is probed at once, with no cycle, and its verdict
// applied; the cycle that follows does not probe it again. With the gate
// shut the fast lane leaves it to the cycle.
func TestFastLane(t *testing.T) {
	s := newScenario(t)
	s.st.setCurrent("n")
	var allowed atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go fastLane(ctx, func() Config { return s.cfg }, s.api, s.st, &allowed, s.w)

	s.script("shut.example.org tcp/443", clean("192.0.2.9"))
	s.see(tunnelled("shut.example.org", 443))
	time.Sleep(1500 * time.Millisecond)
	if s.entry("shut.example.org") != nil {
		t.Fatal("probed with the gate shut")
	}

	allowed.Store(true)
	s.script("new.example.org tcp/443", clean("192.0.2.10"))
	s.see(tunnelled("new.example.org", 443))
	deadline := time.Now().Add(5 * time.Second)
	for s.entry("new.example.org") == nil {
		if time.Now().After(deadline) {
			t.Fatal("no verdict from the fast lane")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if e := s.entry("new.example.org"); e.Verdict != probe.Clean {
		t.Fatalf("verdict %v", e.Verdict)
	}
	for listRules(s.cfg.ListPath) == nil {
		if time.Now().After(deadline) {
			t.Fatal("list not written")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := listRules(s.cfg.ListPath); !slices.Contains(got, "new.example.org") {
		t.Fatalf("list %v", got)
	}

	// the cycle: the shut one is its, the fast lane's is decided
	s.cycle()
	if !s.wasProbed("shut.example.org tcp/443") {
		t.Error("the name the fast lane left is not the cycle's")
	}
	if s.wasProbed("new.example.org tcp/443") {
		t.Error("probed twice")
	}
}

// A name one batch is probing is left by any other.
func TestClaim(t *testing.T) {
	a := claim([]string{"a", "b"})
	t.Cleanup(func() { release(a) })
	if b := claim([]string{"b", "c"}); strings.Join(b, ",") != "c" {
		t.Fatalf("claimed %v", b)
	} else {
		release(b)
	}
	release([]string{"b"})
	if b := claim([]string{"b"}); len(b) != 1 {
		t.Fatalf("released one not claimable: %v", b)
	} else {
		release(b)
	}
}
