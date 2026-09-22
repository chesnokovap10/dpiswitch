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
	Reverts   int           `json:"reverts"` // сколько раз домен уже откатывали
}

// состояние разделено по сетям: ключ -- провайдер (AS...), см. asn.go;
// пока провайдер не определён -- шлюз, см. networkID()
type state struct {
	mu       sync.Mutex
	path     string
	Networks map[string]map[string]*entry `json:"networks"`
	// шлюз -> провайдер за ним
	Attach map[string]attachment `json:"attach,omitempty"`
	// сеть, в которой контроллер работает сейчас: интерфейс читает её
	// отсюда, а не вычисляет сам -- без доступа к прямому пути не может
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
	return os.Rename(tmp, s.path) // атомарно: файл читает и контроллер, и человек
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

// mergeInto вливает в память провайдера всё, что копилось по шлюзам,
// оказавшимся за ним. Из двух вердиктов по домену побеждает более
// свежий. Прежние записи по шлюзам удаляются: память у провайдера одна.
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

// домены, которым сейчас разрешён прямой путь
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

// кандидаты на перепроверку: срок вердикта истёк
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
