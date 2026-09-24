package paths

import (
	"dpiswitch/internal/winexec"
	"fmt"
	"os/user"
)

// Restrict locks a file down: removes inheritance and leaves access only
// to SYSTEM, Administrators and the current user.
//
// Permissions are set by SID, not by group name: on a localized Windows
// "Administrators" has a different name and would not be found.
//
// Caveat: this protects the key from OTHER unprivileged accounts on the
// machine. It does not protect against an administrator or processes under
// your own account -- that would need encryption, and the core must read
// the key in plain text anyway.
func Restrict(path string) error {
	grants := []string{
		"*S-1-5-18:(F)",     // NT AUTHORITY\SYSTEM -- the service runs as it
		"*S-1-5-32-544:(F)", // BUILTIN\Administrators
	}
	if u, err := user.Current(); err == nil && u.Uid != "" {
		grants = append(grants, "*"+u.Uid+":(F)") // so the tray can rewrite the config
	}
	args := append([]string{path, "/inheritance:r"}, prefix("/grant:r", grants)...)
	if out, err := winexec.CombinedOutput("icacls.exe", args...); err != nil {
		return fmt.Errorf("icacls: %v (%s)", err, out)
	}
	return nil
}

func prefix(flag string, items []string) []string {
	out := make([]string, 0, len(items)*2)
	for _, i := range items {
		out = append(out, flag, i)
	}
	return out
}

// GrantUsersModify gives interactive users modify rights on the data
// directory, inherited by newly created files.
//
// Needed because the service runs as SYSTEM: files it creates (state,
// verdict list) are read-only for the user. Without this the tray can
// neither reset verdicts with the panic button nor edit the lists -- and it
// fails silently, at the worst possible moment.
//
// The files holding a private key are unaffected: they are created with
// protected permissions of their own (see WriteSecret) and inherit nothing.
// Hence no /T: the grant is inherited by new files and flows to existing
// ones that inherit anyway, and /T only put this safety at the mercy of how
// icacls treats inheritance flags on files -- an outside review read it as
// opening the keys to every user, and a test had to show it did not.
func GrantUsersModify(dir string) error {
	// S-1-5-32-545 -- BUILTIN\Users; (OI)(CI) -- inherit to files and
	// subfolders; (M) -- modify without changing permissions
	if out, err := winexec.CombinedOutput("icacls.exe", dir,
		"/grant", "*S-1-5-32-545:(OI)(CI)(M)", "/C"); err != nil {
		return fmt.Errorf("icacls: %v (%s)", err, out)
	}
	return nil
}
