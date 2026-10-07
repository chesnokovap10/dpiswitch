package udpguard

import (
	"encoding/json"
	"os"
	"time"

	"dpiswitch/internal/paths"
)

// Status is what the guard is doing, as the service writes it for the UI: the
// service puts the filters in, and the page that shows the setting is the
// tray's, another process. Only codes go in the file; the UI words them in
// its language.
type Status struct {
	State string `json:"state"`
	// Why: what State says it for -- the reason of a wait, the kind of a failure
	Why string `json:"why,omitempty"`
	// Err: the failure as Windows reported it, for State fail
	Err string `json:"err,omitempty"`
	// Rules: the filters in place, for State on
	Rules int `json:"rules,omitempty"`
	// Checked: for State on, a test packet sent out of an uplink adapter by
	// its own address was seen dropped by the engine -- the filters hold, as
	// against only being in it. Not checked is no word against them: the
	// packet may not have been tried, or its drop not recorded.
	Checked bool      `json:"checked,omitempty"`
	At      time.Time `json:"at"`
}

const (
	StateOff  = "off"  // the setting is off
	StateWait = "wait" // on, but not due now: see Why
	StateOn   = "on"   // the filters are in place
	StateFail = "fail" // on and due, but not put in place: see Why and Err
)

const (
	WhyCore    = "core"    // the core is not running
	WhyAdapter = "adapter" // its TUN adapter is down, or has no route out
	WhyTraffic = "traffic" // Windows keeps the programs' traffic from the adapter
	WhyEngine  = "engine"  // Windows Filtering Platform does not answer
	WhyOther   = "other"   // anything else Windows refused
)

// Same: whether two statuses say the same, the time aside -- the file is
// written when something changed, not when the clock did
func (s Status) Same(o Status) bool {
	return s.State == o.State && s.Why == o.Why && s.Err == o.Err && s.Rules == o.Rules && s.Checked == o.Checked
}

// Save replaces the file whole, as the other state files are written: the UI
// reads it while the service writes it
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

// Load reads the file; false when there is none, or it is not ours -- a
// service that has not written it yet, or an older one that never did
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
