//go:build !windows

package hostpolicy

func systemHostsPath() string { return "/etc/hosts" }
