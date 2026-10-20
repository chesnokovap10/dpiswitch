// Package nrpt keeps one rule in Windows' Name Resolution Policy Table: every
// name is asked of the DNS inside the core's TUN adapter, and of nothing else.
//
// Without it Windows asks a name on every adapter at once (Smart Multi-Homed
// Name Resolution): measured 20.10.2026, each one went through the tunnel and
// to the router's DNS on the Wi-Fi adapter both -- the tunnel answered first
// and the other query was cancelled, but it had gone out, and the router asks
// the ISP's resolver. The UDP guard lets it pass: the router is the local
// network. A rule for the namespace "." takes the adapters' servers out of
// the question, the router's, the ISP's and Windows 11's DoH to them alike.
//
// The rule is a registry key the DNS client reads at once (half a second,
// measured): written while the core runs and its adapter takes the traffic,
// taken out when it stops. It outlives a service that dies without taking it
// out -- names then go to an adapter that is not there, and nothing resolves
// until the service starts again and removes it. Its key is a GUID of the
// program's own, so that one is known for ours whoever wrote it.
package nrpt

import (
	"errors"
	"slices"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	// RuleKey: the program's rule among the local ones, under HKLM
	RuleKey = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{6C1F2B5E-9D4A-4E8B-A1C7-3D5F0E2B8A91}`
	// policyKey: the rules of Group Policy. With any there, Windows takes
	// those alone and the local ones are not read.
	policyKey = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
	// configOptions: GenericDNSServers is set (the NRPT's own encoding)
	configOptions = 0x8
	ruleVersion   = 2
	comment       = "DPI Switch: every name through the tunnel's DNS"
)

// Servers: the DNS on the core's TUN adapter. The core takes any :53 that
// comes in by it (dns-hijack), these are the adapter's own.
var Servers = []string{"198.18.0.2", "fdfe:dcba:9876::2"}

// Put writes the rule; changed is false when it stands already as written.
func Put() (changed bool, err error) {
	if present() {
		return false, nil
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, RuleKey, registry.SET_VALUE)
	if err != nil {
		return false, err
	}
	defer k.Close()
	err = errors.Join(
		k.SetStringsValue("Name", []string{"."}),
		k.SetStringValue("GenericDNSServers", strings.Join(Servers, ";")),
		k.SetDWordValue("ConfigOptions", configOptions),
		k.SetDWordValue("Version", ruleVersion),
		k.SetStringValue("IPSECCARestriction", ""),
		k.SetStringValue("Comment", comment),
	)
	if err != nil {
		// half a rule is no rule of ours to leave
		registry.DeleteKey(registry.LOCAL_MACHINE, RuleKey)
		return false, err
	}
	return true, nil
}

// present: the rule is there, as Put writes it
func present() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, RuleKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	name, _, err1 := k.GetStringsValue("Name")
	srv, _, err2 := k.GetStringValue("GenericDNSServers")
	opt, _, err3 := k.GetIntegerValue("ConfigOptions")
	ver, _, err4 := k.GetIntegerValue("Version")
	return errors.Join(err1, err2, err3, err4) == nil && slices.Equal(name, []string{"."}) &&
		srv == strings.Join(Servers, ";") && opt == configOptions && ver == ruleVersion
}

// Lift takes the rule out; removed is false when there was none.
func Lift() (removed bool, err error) {
	err = registry.DeleteKey(registry.LOCAL_MACHINE, RuleKey)
	switch {
	case errors.Is(err, registry.ErrNotExist):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

// Overridden: Group Policy has a rule table of its own, and Windows reads
// no local rule then -- the rule would be written and do nothing. The key
// itself decides, with no rule in it too: a domain's machine may have it
// empty, and the local table is passed over all the same (the review of
// 20.10; NetBird's look at the NRPT found the same).
func Overridden() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, policyKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}
