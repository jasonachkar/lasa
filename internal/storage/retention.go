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

func Prune(path string, keep int) error {
	p, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	h, e := linux.Open("/", strings.TrimPrefix(p, "/"), unix.O_RDONLY|unix.O_DIRECTORY)
	if e != nil {
		return e
	}
	defer h.Close()
	return pruneAt(h, keep)
}

func (s *State) Prune(keep int) error {
	// Open a new directory stream at the pinned inode, starting at entry zero.
	fd, e := unix.Openat(int(s.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	h := os.NewFile(uintptr(fd), s.dir.Name())
	defer h.Close()
	return pruneAt(h, keep)
}

func pruneAt(h *os.File, keep int) error {
	if keep < 1 {
		return fmt.Errorf("retention must be positive")
	}
	names, e := h.Readdirnames(20001)
	if e != nil && !errors.Is(e, io.EOF) {
		return e
	}
	if len(names) > 20000 {
		return fmt.Errorf("state directory entry budget exceeded")
	}
	var managed []string
	for _, name := range names {
		if !snapshotName.MatchString(name) {
			continue
		}
		var st unix.Stat_t
		if e = unix.Fstatat(int(h.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
			return e
		}
		if st.Mode&unix.S_IFMT == unix.S_IFREG && st.Uid == uint32(os.Geteuid()) {
			managed = append(managed, name)
		}
	}
	sort.Strings(managed)
	for len(managed) > keep {
		if e = unix.Unlinkat(int(h.Fd()), managed[0], 0); e != nil {
			return e
		}
		managed = managed[1:]
	}
	return h.Sync()
}
