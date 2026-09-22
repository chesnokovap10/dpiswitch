package ctl

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"

	"dpiswitch/internal/probe"
)

type entry struct {
	Verdict   probe.Verdict `json:"verdict"`
	Reason    string        `json:"reason,omitempty"`
	DecidedAt time.Time     `json:"decided_at"`
	ExpiresAt time.Time     `json:"expires_at"`
	TestedIP  string        `json:"tested_ip,omitempty"`
	Reverts   int           `json:"reverts"` // how many times the domain has been reverted
}

// state is split per network: the key is the ISP (AS...), see asn.go;
// while the ISP is unknown -- the gateway, see networkID()
type state struct {
	mu       sync.Mutex
	path     string
	Networks map[string]map[string]*entry `json:"networks"`
	// gateway -> ISP behind it
	Attach map[string]attachment `json:"attach,omitempty"`
	// the network the controller currently works in: the UI reads it from here
	// instead of computing it -- it cannot without access to the direct path
	Current string `json:"current,omitempty"`
}

func loadState(path string) *state {
	s := &state{path: path, Networks: map[string]map[string]*entry{}}
	b, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	_ = json.Unmarshal(b, s)
	if s.Networks == nil {
		s.Networks = map[string]map[string]*entry{}
	}
	return s
}

func (s *state) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path) // atomic: both the controller and humans read this file
}

func (s *state) attached(gw string) (attachment, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Attach[gw]
	return a, ok
}

func (s *state) attach(gw, asn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Attach == nil {
		s.Attach = map[string]attachment{}
	}
	s.Attach[gw] = attachment{Net: asn, Checked: time.Now()}
}

func (s *state) setCurrent(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Current = id
}

// mergeInto folds everything accumulated under gateways that turned out to
// be behind this ISP into the ISP's memory. Of two verdicts for a domain the
// newer wins. The old per-gateway records are removed: one ISP, one memory.
func (s *state) mergeInto(asn string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Networks[asn] == nil {
		s.Networks[asn] = map[string]*entry{}
	}
	dst := s.Networks[asn]
	n := 0
	for gw, a := range s.Attach {
		if a.Net != asn {
			continue
		}
		for dom, e := range s.Networks[gw] {
			if old, ok := dst[dom]; !ok || e.DecidedAt.After(old.DecidedAt) {
				dst[dom] = e
				n++
			}
		}
		delete(s.Networks, gw)
	}
	return n
}

func (s *state) net(id string) map[string]*entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Networks[id] == nil {
		s.Networks[id] = map[string]*entry{}
	}
	return s.Networks[id]
}

func (s *state) get(id, dom string) (*entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.Networks[id][dom]
	return e, ok
}

func (s *state) put(id, dom string, e *entry) {
	m := s.net(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	m[dom] = e
}

// domains currently allowed to go direct
func (s *state) verified(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	now := time.Now()
	for dom, e := range s.Networks[id] {
		if e.Verdict == probe.Clean && now.Before(e.ExpiresAt) {
			out = append(out, dom)
		}
	}
	sort.Strings(out)
	return out
}

// candidates for re-checking: the verdict has expired
func (s *state) expired(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	now := time.Now()
	for dom, e := range s.Networks[id] {
		if now.After(e.ExpiresAt) {
			out = append(out, dom)
		}
	}
	sort.Strings(out)
	return out
}
