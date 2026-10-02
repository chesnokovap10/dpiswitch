package paths

// The data directory belongs to the service. SYSTEM writes in it, renames
// and deletes there, and runs the core it extracts there -- so nobody else
// may write in it. It used to grant every user modify (the tray wrote its
// settings and lists there), which let any account on the machine:
//
//   - swap logs\ for a junction to an object-manager link, and have SYSTEM
//     create, append to and rename files wherever it pointed -- a way to
//     SYSTEM itself;
//   - drop a source2.conf, a DNS server in settings.json or a list, and send
//     the whole machine's traffic to its own server, the UI key and all;
//   - make "core" a junction, and have SYSTEM take ownership of whatever it
//     pointed at.
//
// Now the directory and everything in it is owned by SYSTEM, writable by
// SYSTEM and the Administrators, readable by Users. What the user changes
// goes to UserDir, writable by the one user who installed the service (the
// owner, kept in the service's registry key). The service reads it through
// ReadUserFile, which follows no link, and never writes there.
//
// Every change of permissions here is made through a handle opened on the
// entry itself (FILE_FLAG_OPEN_REPARSE_POINT) and set on that object alone
// (SetKernelObjectSecurity): nothing follows a link, nothing propagates down
// a tree an attacker may have planted links in. A link found is removed --
// the link, never what it points at.

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// svcSID: the account the directory is locked for, in SDDL. SYSTEM, the
// service's; tests, which cannot set SYSTEM as an owner, put their own.
var svcSID = "SY"

func dirSDDL() string {
	return "O:" + svcSID + "D:P(A;OICI;FA;;;" + svcSID + ")(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"
}

func fileSDDL() string {
	return "O:" + svcSID + "D:P(A;;FA;;;" + svcSID + ")(A;;FA;;;BA)(A;;FRFX;;;BU)"
}

// keySDDL: a file holding private keys -- the owner may read it (the UI
// takes the core API's secret from config.yaml), nobody else.
func keySDDL(owner string) string {
	s := "O:" + svcSID + "D:P(A;;FA;;;" + svcSID + ")(A;;FA;;;BA)"
	if owner != "" {
		s += "(A;;FR;;;" + owner + ")"
	}
	return s
}

// userDirSDDL: the owner lists the directory and adds files to it, and
// modifies the files in it; it cannot delete or replace the directory
// itself, nor make subdirectories -- nothing a junction could go in.
// 0x1200ab: list, add file, read EA and attributes, traverse, read
// permissions, synchronize. 0x1301bf: modify.
func userDirSDDL(owner string) string {
	s := "O:" + svcSID + "D:P(A;OICI;FA;;;" + svcSID + ")(A;OICI;FA;;;BA)"
	if owner != "" {
		s += "(A;;0x1200ab;;;" + owner + ")(A;OIIO;0x1301bf;;;" + owner + ")"
	}
	return s
}

// userKeySDDL: a key-bearing file in UserDir -- the owner's own .conf
func userKeySDDL(owner string) string {
	s := "D:P(A;;FA;;;" + svcSID + ")(A;;FA;;;BA)"
	if owner != "" {
		s += "(A;;FA;;;" + owner + ")"
	}
	return s
}

// keyNames: files in the data directory that hold private keys. The two
// .conf files are there only in an installation from before UserDir, until
// SecureDataDir moves them.
var keyNames = map[string]bool{"config.yaml": true, "source.conf": true, "source2.conf": true}

// SecureDataDir makes the data directory the service's and UserDir the
// owner's, and moves the user's files of an older installation to UserDir.
// Run by the service at every start, before it opens a log, and by the
// installer. owner may be "" -- then nobody but the administrators can write
// in UserDir until the service is installed again.
//
// An error is a directory not wholly locked: the service must not run in it
// (see runService). A file of the user's not moved is not one -- it is
// logged, and moving it is tried again at the next start.
func SecureDataDir(owner string) error {
	enablePrivileges()
	root := DataDir()
	if err := ensureDir(root, dirSDDL()); err != nil {
		return err
	}
	var errs []error
	lockChildren(root, owner, &errs)
	if err := ensureDir(UserDir(), userDirSDDL(owner)); err != nil {
		errs = append(errs, err)
	} else {
		migrate(owner)
	}
	if err := ensureDir(LogDir(), dirSDDL()); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ensureDir: path is a real directory with sddl; a link in its place is
// removed and a directory made anew.
func ensureDir(path, sddl string) error {
	h, info, err := openNoFollow(path, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return createDir(path, sddl)
	case err != nil:
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(h)
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("%s is a link and cannot be removed: %w", path, err)
		}
		return createDir(path, sddl)
	}
	defer windows.CloseHandle(h)
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%s is not a directory", path)
	}
	return setSD(h, path, sddl)
}

func createDir(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	if err := windows.CreateDirectory(name, sa); err != nil {
		return fmt.Errorf("%s not made: %w", path, err)
	}
	// the owner a new object gets is the creator's default one, whatever
	// the descriptor says: set it again
	h, _, err := openNoFollow(path, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return setSD(h, path, sddl)
}

// lockChildren gives everything under dir the service's permissions, and
// removes any link in it. UserDir is left to ensureDir.
func lockChildren(dir, owner string, errs *[]error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		*errs = append(*errs, err)
		return
	}
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		if p == UserDir() {
			continue
		}
		h, info, err := openNoFollow(p, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				*errs = append(*errs, err)
			}
			continue
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			windows.CloseHandle(h)
			log.Printf("data directory: removing the link %s", p)
			if err := os.Remove(p); err != nil {
				*errs = append(*errs, fmt.Errorf("link %s not removed: %w", p, err))
			}
			continue
		}
		isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
		sddl := fileSDDL()
		switch {
		case isDir:
			sddl = dirSDDL()
		case dir == DataDir() && keyNames[strings.ToLower(e.Name())]:
			sddl = keySDDL(owner)
		}
		if err := setSD(h, p, sddl); err != nil {
			*errs = append(*errs, err)
		}
		windows.CloseHandle(h)
		if isDir {
			lockChildren(p, owner, errs)
		}
	}
}

// migrate moves what the user wrote in the data directory of an older
// installation to UserDir: the .conf files, the settings, a reset asked for.
// The lists are copied: the data directory keeps the service's copy the
// core reads.
func migrate(owner string) {
	for _, m := range []struct {
		name string
		sddl string // "" -- UserDir's own, inherited
		keep bool
	}{
		{"source.conf", userKeySDDL(owner), false},
		{"source2.conf", userKeySDDL(owner), false},
		{"settings.json", "", false},
		{"reset-verdicts.request", "", false},
		{DirectList, "", true},
		{TunnelList, "", true},
		{AppsList, "", true},
		{Awg2List, "", true},
	} {
		src, dst := Data(m.name), User(m.name)
		b, err := ReadUserFile(src, 4<<20)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			log.Printf("data directory: %s not moved: %v", m.name, err)
			continue
		}
		if _, err := os.Lstat(dst); errors.Is(err, fs.ErrNotExist) {
			if err := createNew(dst, b, m.sddl); err != nil {
				log.Printf("data directory: %s not moved: %v", m.name, err)
				continue
			}
			log.Printf("data directory: %s moved to %s", m.name, UserDir())
		}
		if !m.keep {
			if err := os.Remove(src); err != nil {
				log.Printf("data directory: %s moved, the old one not removed: %v", m.name, err)
			}
		}
	}
}

// createNew writes a file that must not exist yet, following no link: a
// link in its place makes it fail.
func createNew(path string, data []byte, sddl string) error {
	var sa *windows.SecurityAttributes
	if sddl != "" {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return err
		}
		sa = &windows.SecurityAttributes{SecurityDescriptor: sd}
		sa.Length = uint32(unsafe.Sizeof(*sa))
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("%s not written: %w", path, err)
	}
	f := os.NewFile(uintptr(h), path)
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// openNoFollow opens path itself -- a link as the link -- and tells what it is.
func openNoFollow(path string, access uint32) (windows.Handle, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, info, err
	}
	h, err := windows.CreateFile(name, access|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, info, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return 0, info, &fs.PathError{Op: "stat", Path: path, Err: err}
	}
	return h, info, nil
}

var procSetKernelObjectSecurity = windows.NewLazySystemDLL("advapi32.dll").NewProc("SetKernelObjectSecurity")

// setSD sets owner and DACL on the object behind h, and on it alone.
func setSD(h windows.Handle, path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	r, _, e := procSetKernelObjectSecurity.Call(uintptr(h),
		uintptr(windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION),
		uintptr(unsafe.Pointer(sd)))
	if r == 0 {
		return fmt.Errorf("permissions of %s not set: %w", path, e)
	}
	return nil
}

// ReadUserFile reads a file the user may have written, the way a process
// running as SYSTEM must: not through a link (it would read, as SYSTEM, a
// file the user may not), not through a second hard link, and not past max.
func ReadUserFile(path string, max int64) ([]byte, error) {
	h, info, err := openNoFollow(path, windows.GENERIC_READ)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	switch {
	case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return nil, fmt.Errorf("%s is a link: not read", path)
	case info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0:
		return nil, fmt.Errorf("%s is a directory", path)
	case info.NumberOfLinks > 1:
		return nil, fmt.Errorf("%s has other names (hard links): not read", path)
	case int64(info.FileSizeHigh)<<32|int64(info.FileSizeLow) > max:
		return nil, fmt.Errorf("%s is larger than %d bytes: not read", path, max)
	}
	return io.ReadAll(io.LimitReader(f, max))
}

// enablePrivileges: SYSTEM holds the rights to take ownership and to set
// any permissions, but they are off in its token until asked for. Without
// them an entry someone else made and locked against SYSTEM stays theirs.
func enablePrivileges() {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return
	}
	defer tok.Close()
	for _, name := range []string{"SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege"} {
		var luid windows.LUID
		n, _ := windows.UTF16PtrFromString(name)
		if windows.LookupPrivilegeValue(nil, n, &luid) != nil {
			continue
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		_ = windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
	}
}

// --- the owner ---

// paramsKey: the service's own registry key; only administrators write there
const paramsKey = `SYSTEM\CurrentControlSet\Services\` + AppName + `\Parameters`

// Owner: the SID of the user who installed the service, "" if unknown.
func Owner() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, paramsKey, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("Owner")
	if err != nil || !ValidSID(v) {
		return ""
	}
	return v
}

// SetOwner records the owner; administrators and SYSTEM only.
func SetOwner(sid string) error {
	if !ValidSID(sid) {
		return fmt.Errorf("not a SID: %q", sid)
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, paramsKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("Owner", sid)
}

// ValidSID: s is a user's SID in string form -- nothing else may go into
// an SDDL string
func ValidSID(s string) bool {
	if !userSIDRe.MatchString(s) {
		return false
	}
	_, err := windows.StringToSid(s)
	return err == nil
}

var userSIDRe = regexp.MustCompile(`^S-1-5-21(-\d+){4}$`)

// ResolveOwner: the recorded owner, or, for an installation from before it
// was recorded, the user an older version gave its key files to -- the one
// who loaded the .conf -- or who made the data directory. Recorded once found.
func ResolveOwner() string {
	if o := Owner(); o != "" {
		return o
	}
	o := legacyOwner()
	if o != "" {
		if err := SetOwner(o); err != nil {
			log.Printf("owner %s not recorded: %v", o, err)
		}
	}
	return o
}

var aceSIDRe = regexp.MustCompile(`\(A;[^;]*;[^;]*;;;(S-1-5-21-[0-9-]+)\)`)

func legacyOwner() string {
	for _, p := range []string{Data("source.conf"), Data("config.yaml"), SourceConf()} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			continue
		}
		if m := aceSIDRe.FindStringSubmatch(sd.String()); m != nil && ValidSID(m[1]) {
			return m[1]
		}
	}
	sd, err := windows.GetNamedSecurityInfo(DataDir(), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return ""
	}
	if o, _, err := sd.Owner(); err == nil && o != nil && ValidSID(o.String()) {
		return o.String()
	}
	return ""
}
