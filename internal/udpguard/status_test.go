package udpguard

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStatusFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "udp-guard.json")
	if _, ok := Load(path); ok {
		t.Fatal("a status from no file")
	}
	for _, s := range []Status{
		{State: StateOff},
		{State: StateWait, Why: WhyAdapter},
		{State: StateOn, Rules: 8},
		{State: StateFail, Why: WhyEngine, Err: "The RPC server is unavailable."},
	} {
		if err := s.Save(path); err != nil {
			t.Fatal(err)
		}
		got, ok := Load(path)
		if !ok || !got.Same(s) || got.At.IsZero() || time.Since(got.At) > time.Minute {
			t.Errorf("%+v came back as %+v, %v", s, got, ok)
		}
	}
}

// A file that is not ours -- a broken one, one from a version that wrote
// other states -- is none: the UI shows nothing it does not know.
func TestStatusFileGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "udp-guard.json")
	for _, body := range []string{"", "not json", "{}", `{"state":"maybe"}`, `[1,2]`} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if s, ok := Load(path); ok {
			t.Errorf("%q read as %+v", body, s)
		}
	}
}

// The file is written when something changed, not when the clock did.
func TestStatusSame(t *testing.T) {
	a := Status{State: StateOn, Rules: 8, At: time.Now()}
	b := Status{State: StateOn, Rules: 8, At: time.Now().Add(time.Hour)}
	if !a.Same(b) {
		t.Error("the same state, another time, is another status")
	}
	for _, o := range []Status{
		{State: StateOn, Rules: 6},
		{State: StateWait, Why: WhyCore},
		{State: StateFail, Why: WhyOther, Err: "x"},
	} {
		if a.Same(o) {
			t.Errorf("%+v taken for %+v", a, o)
		}
	}
	if (Status{State: StateFail, Why: WhyOther, Err: "x"}).Same(Status{State: StateFail, Why: WhyOther, Err: "y"}) {
		t.Error("two failures that differ are the same")
	}
}
