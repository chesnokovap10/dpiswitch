package probe

import (
	"fmt"

	"dpiswitch/internal/hostpolicy"
)

var lookupProbeHosts = hostpolicy.Lookup

// Probing the real DNS address of a pinned name is itself a direct leak, even
// when its result would subsequently keep the application's traffic tunneled.
func (d Dialer) checkHosts(domain string) error {
	if !d.RespectHosts || domain == "" {
		return nil
	}
	ips, err := lookupProbeHosts(domain)
	if err != nil {
		return err
	}
	if len(ips) > 0 {
		return fmt.Errorf("direct probe forbidden by system hosts")
	}
	return nil
}

func (d Dialer) forDomain(domain string) Dialer {
	d.guardDomain = domain
	return d
}
