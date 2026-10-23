// Package access evaluates Unix discretionary access, without attempting writes.
// A permitted DAC path is not a claim that LSM, immutable flags or remote
// filesystem authorization would permit a real write.
package access

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type Account struct {
	Name        string
	UID, GID    uint32
	Groups      []uint32
	Home, Shell string
}

func Accounts(passwd, group []byte) ([]Account, error) {
	var out []Account
	names := map[string]bool{}
	gids := map[uint32][]string{}
	for no, line := range strings.Split(string(group), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 4 {
			return nil, fmt.Errorf("group line %d: expected four fields", no+1)
		}
		gid, e := strconv.ParseUint(f[2], 10, 32)
		if e != nil {
			return nil, fmt.Errorf("group line %d: invalid GID", no+1)
		}
		gids[uint32(gid)] = append(gids[uint32(gid)], strings.Split(f[3], ",")...)
	}
	for no, line := range strings.Split(string(passwd), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 7 || f[0] == "" || names[f[0]] {
			return nil, fmt.Errorf("passwd line %d: malformed or duplicate account", no+1)
		}
		uid, e := strconv.ParseUint(f[2], 10, 32)
		if e != nil {
			return nil, fmt.Errorf("passwd line %d: invalid UID", no+1)
		}
		gid, e := strconv.ParseUint(f[3], 10, 32)
		if e != nil {
			return nil, fmt.Errorf("passwd line %d: invalid GID", no+1)
		}
		names[f[0]] = true
		a := Account{Name: f[0], UID: uint32(uid), GID: uint32(gid), Home: f[5], Shell: f[6], Groups: []uint32{uint32(gid)}}
		for id, members := range gids {
			if slices.Contains(members, a.Name) && !slices.Contains(a.Groups, id) {
				a.Groups = append(a.Groups, id)
			}
		}
		slices.Sort(a.Groups)
		out = append(out, a)
		if len(out) > 4096 {
			return nil, fmt.Errorf("local account database exceeds 4096 accounts")
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

type ACLEntry struct {
	Tag, Perm uint16
	ID        uint32
}

func ParseACL(raw []byte) ([]ACLEntry, error) {
	if len(raw) < 4 || binary.LittleEndian.Uint32(raw) != 2 || (len(raw)-4)%8 != 0 || len(raw) > 4096 {
		return nil, fmt.Errorf("invalid POSIX ACL header or length")
	}
	var out []ACLEntry
	seen := map[string]bool{}
	named := false
	for n := 4; n < len(raw); n += 8 {
		e := ACLEntry{binary.LittleEndian.Uint16(raw[n:]), binary.LittleEndian.Uint16(raw[n+2:]), binary.LittleEndian.Uint32(raw[n+4:])}
		if e.Perm > 7 {
			return nil, fmt.Errorf("invalid ACL permission bits")
		}
		switch e.Tag {
		case 1, 4, 16, 32:
			if e.ID != ^uint32(0) {
				return nil, fmt.Errorf("ACL object entry has a named ID")
			}
		case 2, 8:
			named = true
			if e.ID == ^uint32(0) {
				return nil, fmt.Errorf("named ACL entry lacks ID")
			}
		default:
			return nil, fmt.Errorf("unsupported ACL tag")
		}
		key := fmt.Sprint(e.Tag, ":", e.ID)
		if seen[key] {
			return nil, fmt.Errorf("duplicate ACL entry")
		}
		seen[key] = true
		out = append(out, e)
	}
	for _, tag := range []uint16{1, 4, 32} {
		if !seen[fmt.Sprint(tag, ":", ^uint32(0))] {
			return nil, fmt.Errorf("ACL lacks required object entry")
		}
	}
	if named && !seen[fmt.Sprint(uint16(16), ":", ^uint32(0))] {
		return nil, fmt.Errorf("named ACL entries require a mask")
	}
	return out, nil
}

type Metadata struct {
	Path                   string
	Mode, UID, GID         uint32
	Device, Inode, MountID uint64
	ReadOnly               bool
	ChangeTimeSec          int64
	ChangeTimeNS           int64
	ACL                    []ACLEntry
}

func Permissions(m Metadata, a Account) uint16 {
	if a.UID == 0 {
		return 7
	} // root is excluded from unprivileged-writer findings.
	if len(m.ACL) == 0 {
		if a.UID == m.UID {
			return uint16(m.Mode>>6) & 7
		}
		if a.GID == m.GID || slices.Contains(a.Groups, m.GID) {
			return uint16(m.Mode>>3) & 7
		}
		return uint16(m.Mode) & 7
	}
	mask := uint16(7)
	for _, e := range m.ACL {
		if e.Tag == 16 {
			mask = e.Perm
		}
	}
	if a.UID == m.UID {
		for _, e := range m.ACL {
			if e.Tag == 1 {
				return e.Perm
			}
		}
	}
	for _, e := range m.ACL {
		if e.Tag == 2 && e.ID == a.UID {
			return e.Perm & mask
		}
	}
	var p uint16
	matched := false
	for _, e := range m.ACL {
		if e.Tag == 4 && (a.GID == m.GID || slices.Contains(a.Groups, m.GID)) || e.Tag == 8 && (a.GID == e.ID || slices.Contains(a.Groups, e.ID)) {
			p |= e.Perm
			matched = true
		}
	}
	if matched {
		return p & mask
	}
	for _, e := range m.ACL {
		if e.Tag == 32 {
			return e.Perm
		}
	}
	return 0
}

type Result struct {
	Target    string
	Writers   []Account
	Paths     []string
	Metadata  []Metadata
	Uncertain bool
}

func (r Result) Summary() string {
	var names []string
	for _, a := range r.Writers {
		names = append(names, fmt.Sprintf("%s(uid=%d)", a.Name, a.UID))
	}
	return strings.Join(names, ",")
}

// EvaluatePath follows only explicitly requested metadata paths. openat2 confines
// normal symlinks to / and rejects procfs magic links; it never opens contents.
func EvaluatePath(ctx context.Context, path string, accounts []Account) (Result, error) {
	r := Result{Target: path}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 {
		return r, fmt.Errorf("access path must be absolute, normalized and at most 4096 bytes")
	}
	root, e := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return r, e
	}
	defer unix.Close(root)
	metadata := map[string]Metadata{}
	var queue []string
	enqueue := func(p string) {
		for {
			queue = append(queue, p)
			if p == "/" {
				break
			}
			p = filepath.Dir(p)
		}
	}
	enqueue(path)
	resolved := ""
	seen := map[string]bool{}
	for len(queue) > 0 {
		if e := ctx.Err(); e != nil {
			return r, e
		}
		p := queue[0]
		queue = queue[1:]
		if seen[p] {
			continue
		}
		seen[p] = true
		if len(seen) > 512 {
			return r, fmt.Errorf("path/symlink ancestry exceeds 512 metadata entries")
		}
		for _, nofollow := range []bool{true, false} {
			flags := unix.O_PATH | unix.O_CLOEXEC
			if nofollow {
				flags |= unix.O_NOFOLLOW
			}
			rel := strings.TrimPrefix(p, "/")
			if rel == "" {
				rel = "."
			}
			fd, e := unix.Openat2(root, rel, &unix.OpenHow{Flags: uint64(flags), Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
			if e != nil {
				return r, fmt.Errorf("inspect metadata %s: %w", p, e)
			}
			m, e := readMetadata(fd)
			unix.Close(fd)
			if e != nil {
				return r, fmt.Errorf("metadata for %s: %w", p, e)
			}
			if nofollow && m.Mode&unix.S_IFMT != unix.S_IFLNK {
				metadata[m.Path] = m
				if p == path {
					resolved = m.Path
				}
				if m.Path != p {
					enqueue(m.Path)
				}
				break
			}
			metadata[m.Path] = m
			if !nofollow {
				if p == path {
					resolved = m.Path
				}
				if m.Path != p {
					enqueue(m.Path)
				}
			}
		}
	}
	if resolved == "" {
		return r, fmt.Errorf("could not resolve requested metadata path")
	}
	r.Target = resolved
	traversable := func(p string, a Account) bool {
		for q := filepath.Dir(p); ; q = filepath.Dir(q) {
			m, ok := metadata[q]
			if !ok || m.Mode&unix.S_IFMT != unix.S_IFDIR || Permissions(m, a)&1 == 0 {
				return false
			}
			if q == "/" {
				return true
			}
		}
	}
	for _, m := range metadata {
		if e := ctx.Err(); e != nil {
			return r, e
		}
		rel := strings.TrimPrefix(m.Path, "/")
		if rel == "" {
			rel = "."
		}
		fd, e := unix.Openat2(root, rel, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
		if e != nil {
			return r, fmt.Errorf("metadata path changed during access inspection: %w", e)
		}
		again, e := readMetadata(fd)
		unix.Close(fd)
		if e != nil {
			return r, e
		}
		if again.Inode != m.Inode || again.Device != m.Device || again.ChangeTimeSec != m.ChangeTimeSec || again.ChangeTimeNS != m.ChangeTimeNS || again.ReadOnly != m.ReadOnly || again.MountID != m.MountID {
			return r, fmt.Errorf("metadata path changed during access inspection; rerun the scan")
		}
	}
	target, ok := metadata[resolved]
	if !ok {
		return r, fmt.Errorf("resolved target missing metadata")
	}
	for _, a := range accounts {
		if a.UID == 0 {
			continue
		}
		allowed := !target.ReadOnly && ((target.Mode&unix.S_IFMT == unix.S_IFREG || target.Mode&unix.S_IFMT == unix.S_IFSOCK) && Permissions(target, a)&2 != 0 || target.Mode&unix.S_IFMT == unix.S_IFDIR && Permissions(target, a)&3 == 3) && traversable(resolved, a)
		if allowed {
			r.Paths = append(r.Paths, resolved)
		}
		for p, m := range metadata {
			if p == "/" {
				continue
			}
			parent, ok := metadata[filepath.Dir(p)]
			if !ok || parent.ReadOnly {
				continue
			}
			if parent.MountID == 0 || m.MountID == 0 {
				if Permissions(parent, a)&3 == 3 && traversable(p, a) {
					r.Uncertain = true
				}
				continue
			}
			if parent.MountID != m.MountID {
				continue
			}
			if parent.Mode&unix.S_ISVTX != 0 && a.UID != parent.UID && a.UID != m.UID {
				continue
			}
			if Permissions(parent, a)&3 == 3 && traversable(p, a) {
				allowed = true
				r.Paths = append(r.Paths, p)
			}
		}
		if allowed {
			r.Writers = append(r.Writers, a)
		}
	}
	for _, m := range metadata {
		r.Metadata = append(r.Metadata, m)
	}
	sort.Slice(r.Metadata, func(i, j int) bool { return r.Metadata[i].Path < r.Metadata[j].Path })
	slices.Sort(r.Paths)
	r.Paths = slices.Compact(r.Paths)
	return r, nil
}
func readMetadata(fd int) (Metadata, error) {
	var st unix.Stat_t
	if e := unix.Fstat(fd, &st); e != nil {
		return Metadata{}, e
	}
	name, e := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if e != nil {
		return Metadata{}, e
	}
	if strings.HasSuffix(name, " (deleted)") {
		return Metadata{}, fmt.Errorf("path changed during metadata inspection")
	}
	m := Metadata{Path: name, Mode: st.Mode, UID: st.Uid, GID: st.Gid, Device: uint64(st.Dev), Inode: st.Ino, ChangeTimeSec: st.Ctim.Sec, ChangeTimeNS: st.Ctim.Nsec}
	var fs unix.Statfs_t
	if e := unix.Fstatfs(fd, &fs); e != nil {
		return m, e
	}
	m.ReadOnly = fs.Flags&unix.ST_RDONLY != 0
	var sx unix.Statx_t
	if e := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &sx); e == nil && sx.Mask&unix.STATX_MNT_ID != 0 {
		m.MountID = sx.Mnt_id
	}
	if st.Mode&unix.S_IFMT == unix.S_IFREG || st.Mode&unix.S_IFMT == unix.S_IFDIR {
		buf := make([]byte, 4096)
		n, e := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", fd), "system.posix_acl_access", buf)
		if e == nil {
			m.ACL, e = ParseACL(buf[:n])
			if e != nil {
				return m, e
			}
		} else if !errors.Is(e, unix.ENODATA) && !errors.Is(e, unix.EOPNOTSUPP) {
			return m, e
		}
	}
	return m, nil
}
