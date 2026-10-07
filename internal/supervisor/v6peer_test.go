package supervisor

import (
	"testing"
	"time"
)

// A hold is for the peer it was found on: another .conf under the same
// name -- another server -- is not held to it; one with no peer known is
// checked once more
func TestSamePeers(t *testing.T) {
	at := time.Now()
	h := v6Held{"awg1": at, "awg2": at}
	got := h.samePeers(map[string]string{"awg1": "aa", "awg2": "bb"}, map[string]string{"awg1": "aa", "awg2": "cc"})
	if _, ok := got["awg1"]; !ok {
		t.Error("the same peer's hold dropped")
	}
	if _, ok := got["awg2"]; ok {
		t.Error("another peer held to the old one's answer")
	}
	if got := h.samePeers(map[string]string{}, map[string]string{"awg1": "aa"}); len(got) != 0 {
		t.Errorf("holds with no peer known kept: %v", got)
	}
}
