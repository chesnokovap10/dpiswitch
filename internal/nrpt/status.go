package nrpt

import (
	"encoding/json"
	"os"
	"time"

	"dpiswitch/internal/paths"
)

// Status: what the service last found of the rule, for the UI -- written by
// the service when it changes (see supervisor.holdNRPT)
type Status struct {
	State string `json:"state"`
	// Why: what State says it for -- the reason of a wait, the kind of a failure
	Why string `json:"why,omitempty"`
	// Err: the failure as Windows reported it, for State fail
	Err string    `json:"err,omitempty"`
	At  time.Time `json:"at"`
}

const (
	StateOff  = "off"  // the setting is off
	StateWait = "wait" // on, but not due now: see Why
	StateOn   = "on"   // the rule is in place
	StateFail = "fail" // on and due, but not in place: see Why and Err
)

const (
	WhyCore    = "core"    // the core is not running
	WhyAdapter = "adapter" // its TUN adapter is down, or has no route out
	WhyTraffic = "traffic" // Windows keeps the programs' traffic from the adapter
	WhyPolicy  = "policy"  // Group Policy has rules of its own (see Overridden)
	WhyIgnored = "ignored" // written, and the DNS client does not apply it (see Effective)
	WhyOther   = "other"   // the registry refused
)

// Same: whether two statuses say the same, the time aside
func (s Status) Same(o Status) bool {
	return s.State == o.State && s.Why == o.Why && s.Err == o.Err
}

// Save replaces the file whole: the UI reads it while the service writes it
func (s Status) Save(path string) error {
	if s.At.IsZero() {
		s.At = time.Now()
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return paths.ReplaceFile(path, append(b, '\n'))
}

// Load reads the file; false when there is none, or it is not ours
func Load(path string) (Status, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Status{}, false
	}
	var s Status
	if json.Unmarshal(b, &s) != nil {
		return Status{}, false
	}
	switch s.State {
	case StateOff, StateWait, StateOn, StateFail:
		return s, true
	}
	return Status{}, false
}
