// Package linux provides bounded, symlink-rejecting Linux metadata access.
package linux

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type Reader interface {
	Read(string) ([]byte, error)
	Readlink(string) (string, error)
	Names(string, int) ([]string, bool, error)
}
type FS struct {
	Root  string
	Limit int64
}

func valid(p string) bool {
	return p != "" && !filepath.IsAbs(p) && filepath.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../")
}
func Open(root, path string, flags int) (*os.File, error) {
	if !valid(path) {
		return nil, fmt.Errorf("invalid relative metadata path %q", path)
	}
	fd, e := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	n, e := unix.Openat2(fd, path, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(n), filepath.Join(root, path)), nil
}
func (f FS) Read(p string) ([]byte, error) {
	h, e := Open(f.Root, p, unix.O_RDONLY|unix.O_NONBLOCK)
	if e != nil {
		return nil, e
	}
	defer h.Close()
	limit := f.Limit
	if limit <= 0 {
		limit = 1 << 20
	}
	b, e := io.ReadAll(io.LimitReader(h, limit+1))
	if e == nil && int64(len(b)) > limit {
		return nil, fmt.Errorf("metadata exceeds %d-byte read budget", limit)
	}
	return b, e
}
func (f FS) Readlink(p string) (string, error) {
	if !valid(p) {
		return "", fmt.Errorf("invalid link path")
	}
	parent := filepath.Dir(p)
	var dir *os.File
	var e error
	if parent == "." {
		dir, e = os.Open(f.Root)
	} else {
		dir, e = Open(f.Root, parent, unix.O_PATH|unix.O_DIRECTORY)
	}
	if e != nil {
		return "", e
	}
	defer dir.Close()
	b := make([]byte, 4097)
	n, e := unix.Readlinkat(int(dir.Fd()), filepath.Base(p), b)
	if e != nil {
		return "", e
	}
	if n >= len(b) {
		return "", fmt.Errorf("link target exceeds budget")
	}
	return string(b[:n]), nil
}
func (f FS) Names(p string, limit int) ([]string, bool, error) {
	var h *os.File
	var e error
	if p == "." {
		h, e = os.Open(f.Root)
	} else {
		h, e = Open(f.Root, p, unix.O_RDONLY|unix.O_DIRECTORY)
	}
	if e != nil {
		return nil, false, e
	}
	defer h.Close()
	names, e := h.Readdirnames(limit + 1)
	if e != nil && e != io.EOF {
		return nil, false, e
	}
	truncated := len(names) > limit
	if truncated {
		names = names[:limit]
	}
	return names, truncated, nil
}

// Executable pins the procfs executable magic link intentionally. Only metadata
// of this kernel-supplied executable reference is accessed; no file is read.
func (f FS) Executable(pid string) (string, uint64, uint64, error) {
	if _, e := strconv.ParseUint(pid, 10, 31); e != nil {
		return "", 0, 0, fmt.Errorf("invalid executable PID")
	}
	dir, e := Open(f.Root, pid, unix.O_PATH|unix.O_DIRECTORY)
	if e != nil {
		return "", 0, 0, e
	}
	defer dir.Close()
	fd, e := unix.Openat(int(dir.Fd()), "exe", unix.O_PATH|unix.O_CLOEXEC, 0)
	if e != nil {
		return "", 0, 0, e
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if e = unix.Fstat(fd, &st); e != nil {
		return "", 0, 0, e
	}
	name, e := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	return name, st.Ino, uint64(st.Dev), e
}
