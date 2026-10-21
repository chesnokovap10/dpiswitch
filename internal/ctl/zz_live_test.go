//go:build localbench

package ctl

import (
	"testing"

	"dpiswitch/internal/paths"
)

func TestLiveCDNRound(t *testing.T) {
	st := loadState(paths.State())
	id := st.current()
	b := loadCDNBook(paths.CDNBook())
	cands := st.cdnCandidates(id)
	t.Logf("candidates %v", cands)
	t.Logf("stale %v", b.stale(cands))
	hosts := st.cdnHosts(id, "googlevideo.com")
	t.Logf("hosts %v", hosts)
	pass := secretFromConfig(paths.Config())
	for _, h := range hosts {
		sans, err := fetchCert("127.0.0.1:7891", pass, h)
		t.Logf("%s: %d names, err %v", h, len(sans), err)
	}
}
