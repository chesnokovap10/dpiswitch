package ctl

import (
	"strings"
	"testing"
)

// The local link as this machine has it: no loopback, no TUN, no
// link-local address -- each "index=address/bits".
func TestLocalLinkHere(t *testing.T) {
	for _, f := range strings.Fields(localLink()) {
		for _, bad := range []string{"=127.", "=198.18.", "=198.19.", "=169.254."} {
			if strings.Contains(f, bad) {
				t.Errorf("%s in the local link", f)
			}
		}
	}
}
