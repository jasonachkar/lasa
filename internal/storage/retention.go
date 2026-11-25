package storage

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	linux "github.com/jasonachkar/lasa/internal/platform/linux"
	"golang.org/x/sys/unix"
)

var snapshotName = regexp.MustCompile(`^scan-[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-[a-f0-9]{32}\.json$`)

// Prune keeps the newest keep managed snapshots in path and returns the names
// it removed.
func Prune(path string, keep int) ([]string, error) {
	p, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	h, e := linux.Open("/", strings.TrimPrefix(p, "/"), unix.O_RDONLY|unix.O_DIRECTORY)
	if e != nil {
		return nil, e
	}
	defer h.Close()
	return pruneAt(h, keep)
}

// Prune keeps the newest keep managed snapshots and returns the removed names.
func (s *State) Prune(keep int) ([]string, error) {
	h, e := s.stream()
	if e != nil {
		return nil, e
	}
	defer h.Close()
	return pruneAt(h, keep)
}

// stream opens a new directory stream at the pinned inode, starting at entry zero.
func (s *State) stream() (*os.File, error) {
	fd, e := unix.Openat(int(s.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), s.dir.Name()), nil
}

// managedSnapshots lists scanner-named regular snapshots owned by the
// scanner user, oldest first. Names embed a sortable UTC timestamp.
func managedSnapshots(h *os.File) ([]string, error) {
	names, e := h.Readdirnames(20001)
	if e != nil && !errors.Is(e, io.EOF) {
		return nil, e
	}
	if len(names) > 20000 {
		return nil, fmt.Errorf("state directory entry budget exceeded")
	}
	var managed []string
	for _, name := range names {
		if !snapshotName.MatchString(name) {
			continue
		}
		var st unix.Stat_t
		if e = unix.Fstatat(int(h.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
			return nil, e
		}
		if st.Mode&unix.S_IFMT == unix.S_IFREG && int64(st.Uid) == int64(os.Geteuid()) {
			managed = append(managed, name)
		}
	}
	sort.Strings(managed)
	return managed, nil
}

func pruneAt(h *os.File, keep int) ([]string, error) {
	if keep < 1 {
		return nil, fmt.Errorf("retention must be positive")
	}
	managed, e := managedSnapshots(h)
	if e != nil {
		return nil, e
	}
	var removed []string
	for len(managed) > keep {
		if e = unix.Unlinkat(int(h.Fd()), managed[0], 0); e != nil {
			return removed, e
		}
		removed = append(removed, managed[0])
		managed = managed[1:]
	}
	return removed, h.Sync()
}

// Latest reads the newest managed snapshot, up to limit bytes. It returns an
// empty name when the directory holds no snapshot.
func (s *State) Latest(limit int64) (string, []byte, error) {
	h, e := s.stream()
	if e != nil {
		return "", nil, e
	}
	defer h.Close()
	managed, e := managedSnapshots(h)
	if e != nil || len(managed) == 0 {
		return "", nil, e
	}
	name := managed[len(managed)-1]
	fd, e := unix.Openat(int(s.dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return name, nil, e
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return name, nil, e
	}
	if !st.Mode().IsRegular() {
		return name, nil, fmt.Errorf("snapshot %s is not a regular file", name)
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e == nil && int64(len(b)) > limit {
		e = fmt.Errorf("snapshot %s exceeds %d bytes", name, limit)
	}
	return name, b, e
}
