package hostpolicy

import "golang.org/x/sys/windows"

func systemHostsPath() string {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return ""
	} // Lookup returns an error, never a DNS fallback.
	return dir + "/drivers/etc/hosts"
}
