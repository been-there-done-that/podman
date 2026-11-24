//go:build !remote

package libpod

// Checkpoint/restore of rootful containers with a user namespace.
//
// CRIU restores the process tree from inside the container's user namespace, as the container's mapped root.
// That uid must read the checkpoint images and look up the container's bind-mount sources (hosts, resolv.conf,
// hostname, .containerenv, /dev/shm, named volumes), which Podman keeps under root-only (0700) directories.
//
// For the duration of the restore only, we grant exactly that uid:
//   - ownership of the checkpoint image files (handed back to root afterwards), and
//   - search-only (x) permission on the directories on the path to its own bind-mount sources, through a
//     POSIX ACL entry naming that uid. No other uid gains anything, nothing becomes listable or writable, and
//     the entries are removed (and the original modes restored) when the restore returns.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/sys/unix"
)

const aclXattrName = "system.posix_acl_access"

// POSIX ACL xattr format (linux/posix_acl_xattr.h).
const (
	aclXattrVersion = 2 // header version
	aclTagUserObj   = 0x01
	aclTagUser      = 0x02
	aclTagGroupObj  = 0x04
	aclTagMask      = 0x10
	aclTagOther     = 0x20
	aclUndefinedID  = 0xffffffff
)

type usernsRestoreGrant struct {
	uid, gid int
	images   string
	modes    map[string]os.FileMode
	dirs     []string
}

type aclEntry struct {
	tag  uint16
	perm uint16
	id   uint32
}

func parseACLXattr(b []byte) ([]aclEntry, error) {
	if len(b) < 4 || (len(b)-4)%8 != 0 || binary.LittleEndian.Uint32(b) != aclXattrVersion {
		return nil, errors.New("unexpected ACL format")
	}
	var ents []aclEntry
	for o := 4; o < len(b); o += 8 {
		ents = append(ents, aclEntry{binary.LittleEndian.Uint16(b[o:]), binary.LittleEndian.Uint16(b[o+2:]), binary.LittleEndian.Uint32(b[o+4:])})
	}
	return ents, nil
}

func encodeACLXattr(ents []aclEntry) []byte {
	b := make([]byte, 4+8*len(ents))
	binary.LittleEndian.PutUint32(b, aclXattrVersion)
	for i, e := range ents {
		o := 4 + 8*i
		binary.LittleEndian.PutUint16(b[o:], e.tag)
		binary.LittleEndian.PutUint16(b[o+2:], e.perm)
		binary.LittleEndian.PutUint32(b[o+4:], e.id)
	}
	return b
}

// lockRestoreACLs serialises the read-modify-write of ACLs on shared parent directories between Podman processes.
func lockRestoreACLs() (func(), error) {
	f, err := os.OpenFile("/run/containers/restore-acl.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}

// addSearchACL adds a search-only entry for uid to p's ACL (creating a minimal ACL from the mode if none).
// Returns false if p already lets uid search (nothing to undo).
func addSearchACL(p string, uid int) (bool, error) {
	st, err := os.Stat(p)
	if err != nil {
		return false, err
	}
	perm := uint16(st.Mode().Perm())
	if perm&0o001 != 0 {
		return false, nil
	}
	if sys, ok := st.Sys().(*unix.Stat_t); ok && int(sys.Uid) == uid {
		return false, nil
	}
	var ents []aclEntry
	buf := make([]byte, 4096)
	if n, err := unix.Getxattr(p, aclXattrName, buf); err == nil {
		if ents, err = parseACLXattr(buf[:n]); err != nil {
			return false, err
		}
	} else if errors.Is(err, unix.ENODATA) {
		ents = []aclEntry{
			{aclTagUserObj, (perm >> 6) & 7, aclUndefinedID},
			{aclTagGroupObj, (perm >> 3) & 7, aclUndefinedID},
			{aclTagMask, (perm >> 3) & 7, aclUndefinedID},
			{aclTagOther, perm & 7, aclUndefinedID},
		}
	} else {
		return false, err
	}
	for _, e := range ents {
		if e.tag == aclTagUser && int(e.id) == uid {
			return false, nil
		}
	}
	// Entries must stay sorted by tag, then id: insert the user entry after USER_OBJ / other USER entries.
	out := make([]aclEntry, 0, len(ents)+1)
	added := false
	for _, e := range ents {
		if !added && (e.tag > aclTagUser || (e.tag == aclTagUser && e.id > uint32(uid))) {
			out = append(out, aclEntry{aclTagUser, 1, uint32(uid)})
			added = true
		}
		if e.tag == aclTagMask {
			e.perm |= 1
		}
		out = append(out, e)
	}
	if !added {
		out = append(out, aclEntry{aclTagUser, 1, uint32(uid)})
	}
	if err := unix.Setxattr(p, aclXattrName, encodeACLXattr(out), 0); err != nil {
		return false, fmt.Errorf("granting search on %s: %w", p, err)
	}
	return true, nil
}

// removeSearchACL removes uid's entry; when only the base entries are left, the ACL is dropped and the group
// bits of the mode are restored from GROUP_OBJ.
func removeSearchACL(p string, uid int) {
	buf := make([]byte, 4096)
	n, err := unix.Getxattr(p, aclXattrName, buf)
	if err != nil {
		return
	}
	ents, err := parseACLXattr(buf[:n])
	if err != nil {
		return
	}
	var out []aclEntry
	named := 0
	var groupObj uint16
	for _, e := range ents {
		if e.tag == aclTagUser && int(e.id) == uid {
			continue
		}
		if e.tag == aclTagUser || e.tag == 0x08 /* ACL_GROUP */ {
			named++
		}
		if e.tag == aclTagGroupObj {
			groupObj = e.perm
		}
		out = append(out, e)
	}
	if named == 0 {
		st, err := os.Stat(p)
		if err != nil {
			return
		}
		if err := unix.Removexattr(p, aclXattrName); err == nil {
			_ = os.Chmod(p, (st.Mode().Perm()&^0o070)|os.FileMode(groupObj<<3))
		}
		return
	}
	_ = unix.Setxattr(p, aclXattrName, encodeACLXattr(out), 0)
}

// allowSearch gives g.uid search permission on dir and each parent up to the first one everyone may search.
func (g *usernsRestoreGrant) allowSearch(dir string) error {
	for p := dir; p != "/" && p != "."; p = filepath.Dir(p) {
		st, err := os.Stat(p)
		if err != nil {
			return err
		}
		if st.Mode().Perm()&0o001 != 0 {
			return nil
		}
		changed, err := addSearchACL(p, g.uid)
		if err != nil {
			return err
		}
		if changed {
			g.dirs = append(g.dirs, p)
		}
	}
	return nil
}

// grantUsernsRestoreAccess prepares the paths CRIU needs. The caller must call revoke() when the restore returns.
func (c *Container) grantUsernsRestoreAccess() (*usernsRestoreGrant, error) {
	g := &usernsRestoreGrant{uid: c.RootUID(), gid: c.RootGID(), images: c.CheckpointPath()}
	if g.uid == 0 {
		return g, nil
	}
	// The restored init task can open images before its uid map is written, while it is still the overflow
	// uid, so the images are also made readable (and their directory searchable) by others for the duration
	// of the restore. Only root and g.uid can reach this directory: its parents are 0700 plus g.uid's entry.
	g.modes = map[string]os.FileMode{}
	if err := filepath.WalkDir(g.images, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		g.modes[p] = info.Mode().Perm()
		if err := os.Lchown(p, g.uid, g.gid); err != nil {
			return err
		}
		extra := os.FileMode(0o004)
		if d.IsDir() {
			extra = 0o005
		}
		return os.Chmod(p, info.Mode().Perm()|extra)
	}); err != nil {
		g.revoke()
		return nil, err
	}
	dirs := []string{c.bundlePath(), c.state.RunDir}
	for _, v := range c.config.NamedVolumes {
		vol, err := c.runtime.GetVolume(v.Name)
		if err != nil {
			g.revoke()
			return nil, err
		}
		if mp, err := vol.MountPoint(); err == nil && mp != "" {
			dirs = append(dirs, filepath.Dir(mp))
		}
	}
	unlock, err := lockRestoreACLs()
	if err != nil {
		g.revoke()
		return nil, err
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if err := g.allowSearch(d); err != nil {
			unlock()
			g.revoke()
			return nil, err
		}
	}
	unlock()
	return g, nil
}

// revoke removes every grant: ACL entries off (original modes back) and checkpoint images owned by root again.
func (g *usernsRestoreGrant) revoke() {
	if g == nil {
		return
	}
	if len(g.dirs) > 0 {
		if unlock, err := lockRestoreACLs(); err == nil {
			for _, dir := range slices.Backward(g.dirs) {
				removeSearchACL(dir, g.uid)
			}
			unlock()
		}
	}
	g.dirs = nil
	for p, mode := range g.modes {
		_ = os.Lchown(p, 0, 0)
		_ = os.Chmod(p, mode)
	}
	g.modes = nil
}

// setupNetworkAfterRestore is completeNetworkSetup without syncContainer (which would reload the pre-checkpoint PID).
func (c *Container) setupNetworkAfterRestore() error {
	netDisabled, err := c.NetworkDisabled()
	if err != nil {
		return err
	}
	if netDisabled || c.config.NetNsCtr != "" {
		return nil
	}
	// The restored process may already have exited (e.g. a restarted relative nanosleep that returns early);
	// behave like a restore without a user namespace and let the state sync mark the container exited.
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/ns/net", c.state.PID)); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := c.runtime.setupNetNS(c); err != nil {
		return err
	}
	if err := c.save(); err != nil {
		return err
	}
	if err := c.addHosts(); err != nil {
		return err
	}
	return c.addResolvConf()
}
