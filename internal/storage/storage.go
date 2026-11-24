// Package storage persists private files using directory-relative atomic operations.
package storage

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	linux "github.com/jasonachkar/lasa/internal/platform/linux"
	"golang.org/x/sys/unix"
)

func parent(path string) (*os.File, string, error) {
	absolute, e := filepath.Abs(path)
	if e != nil {
		return nil, "", e
	}
	if strings.ContainsRune(path, 0) || filepath.Base(absolute) == "/" {
		return nil, "", fmt.Errorf("invalid file path")
	}
	h, e := linux.Open("/", strings.TrimPrefix(filepath.Dir(absolute), "/"), unix.O_RDONLY|unix.O_DIRECTORY)
	if filepath.Dir(absolute) == "/" {
		h, e = linux.Open("/", ".", unix.O_RDONLY|unix.O_DIRECTORY)
	}
	return h, filepath.Base(absolute), e
}
func Atomic(path string, b []byte) error {
	dir, base, e := parent(path)
	if e != nil {
		return fmt.Errorf("open output directory: %w", e)
	}
	defer dir.Close()
	return atomicAt(dir, base, b)
}

func atomicAt(dir *os.File, base string, b []byte) error {
	var e error
	var parentStat unix.Stat_t
	if e = unix.Fstat(int(dir.Fd()), &parentStat); e != nil {
		return e
	}
	if !ownerAllowed(parentStat.Uid, os.Geteuid(), os.Getenv("SUDO_UID")) && parentStat.Mode&unix.S_ISVTX == 0 {
		return fmt.Errorf("output directory is owned by uid %d; it must be owned by the scanner user (uid %d), root, or the sudo invoking user, or be a sticky directory such as /tmp", parentStat.Uid, os.Geteuid())
	}
	if parentStat.Mode&0022 != 0 && parentStat.Mode&unix.S_ISVTX == 0 {
		return fmt.Errorf("output parent is writable by other users without sticky-bit protection")
	}
	var st unix.Stat_t
	if e = unix.Fstatat(int(dir.Fd()), base, &st, unix.AT_SYMLINK_NOFOLLOW); e == nil && st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("output %q exists and is not a regular file", base)
	} else if e != nil && !errors.Is(e, unix.ENOENT) {
		return e
	}
	var token [12]byte
	if _, e = rand.Read(token[:]); e != nil {
		return e
	}
	tmp := ".lasa-" + hex.EncodeToString(token[:]) + ".tmp"
	fd, e := unix.Openat(int(dir.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	h := os.NewFile(uintptr(fd), tmp)
	defer func() { _ = h.Close(); _ = unix.Unlinkat(int(dir.Fd()), tmp, 0) }()
	if owner, group, ok := invokingOwner(parentStat.Uid); ok {
		// A sudo scan writing into the invoking user's private directory
		// hands the private report to that user.
		if e = unix.Fchown(fd, owner, group); e != nil {
			return fmt.Errorf("assign report to the invoking user: %w", e)
		}
	}
	if _, e = h.Write(b); e != nil {
		return e
	}
	if e = h.Sync(); e != nil {
		return e
	}
	if e = h.Close(); e != nil {
		return e
	}
	if e = unix.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), base); e != nil {
		return e
	}
	if e = dir.Sync(); e != nil {
		return fmt.Errorf("file renamed but directory durability uncertain: %w", e)
	}
	return nil
}
func Read(path string, limit int64) ([]byte, error) {
	absolute, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	h, e := linux.OpenRegular("/", strings.TrimPrefix(absolute, "/"))
	if e != nil {
		return nil, e
	}
	defer h.Close()
	b, e := io.ReadAll(io.LimitReader(h, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("input exceeds %d bytes", limit)
	}
	return b, nil
}

// State keeps the checked directory pinned for the lifetime of the daemon.
type State struct {
	dir *os.File
}

func OpenState(path string) (*State, error) {
	p, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	defer func() { _ = unix.Close(fd) }()
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(e, unix.ENOENT) {
			if e = unix.Mkdirat(fd, part, 0700); e != nil && !errors.Is(e, unix.EEXIST) {
				return nil, e
			}
			next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if e != nil {
			return nil, e
		}
		_ = unix.Close(fd)
		fd = next
	}
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return nil, e
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return nil, fmt.Errorf("state directory must be owned by the scanner user and grant no group or other access")
	}
	dir := os.NewFile(uintptr(fd), p)
	fd = -1 // State owns the descriptor after this point.
	return &State{dir: dir}, nil
}

func (s *State) Close() error { return s.dir.Close() }

func (s *State) WriteSnapshot(name string, data []byte) error {
	if !snapshotName.MatchString(name) {
		return fmt.Errorf("invalid snapshot name")
	}
	return atomicAt(s.dir, name, data)
}

func (s *State) Lock() (*os.File, error) {
	const name = ".daemon.lock"
	fd, e := unix.Openat(int(s.dir.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	h := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		_ = h.Close()
		return nil, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 || st.Nlink != 1 {
		_ = h.Close()
		return nil, fmt.Errorf("daemon lock must be a private regular file owned by the scanner")
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		_ = h.Close()
		return nil, fmt.Errorf("another daemon holds this state directory: %w", e)
	}
	return h, nil
}

// ownerAllowed reports whether a directory owner is trusted for private
// output: the scanner user, root, or, for a root scan started through sudo,
// the invoking user. That user already controls a root session, so writing
// into their own private directory does not cross a trust boundary; the
// directory must still not be writable by group or other users.
func ownerAllowed(owner uint32, euid int, sudoUID string) bool {
	if owner == uint32(euid) || owner == 0 {
		return true
	}
	if euid != 0 || sudoUID == "" {
		return false
	}
	invoking, e := strconv.ParseUint(sudoUID, 10, 32)
	return e == nil && uint32(invoking) == owner
}

// invokingOwner returns the sudo invoking user and group when running as root
// and the destination directory belongs to that user.
func invokingOwner(dirOwner uint32) (int, int, bool) {
	if os.Geteuid() != 0 || dirOwner == 0 {
		return 0, 0, false
	}
	uid, e1 := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	gid, e2 := strconv.ParseUint(os.Getenv("SUDO_GID"), 10, 32)
	// IDs above MaxInt32 are invalid; the bound also keeps the int
	// conversion exact on 32-bit platforms, where -1 would mean "unchanged".
	if e1 != nil || e2 != nil || uid > math.MaxInt32 || gid > math.MaxInt32 || uint32(uid) != dirOwner {
		return 0, 0, false
	}
	return int(uid), int(gid), true
}
