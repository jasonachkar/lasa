// Package storage persists private files using directory-relative atomic operations.
package storage

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	var parentStat unix.Stat_t
	if e = unix.Fstat(int(dir.Fd()), &parentStat); e != nil {
		return e
	}
	if parentStat.Uid != uint32(os.Geteuid()) && parentStat.Uid != 0 && parentStat.Mode&unix.S_ISVTX == 0 {
		return fmt.Errorf("output parent must be owned by the scanner user or root")
	}
	if parentStat.Mode&0022 != 0 && parentStat.Mode&unix.S_ISVTX == 0 {
		return fmt.Errorf("output parent is writable by other users without sticky-bit protection")
	}
	var st unix.Stat_t
	if e = unix.Fstatat(int(dir.Fd()), base, &st, unix.AT_SYMLINK_NOFOLLOW); e == nil && st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("output %q exists and is not a regular file", path)
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
	h, e := linux.Open("/", strings.TrimPrefix(absolute, "/"), unix.O_RDONLY|unix.O_NONBLOCK)
	if e != nil {
		return nil, e
	}
	defer h.Close()
	st, e := h.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("input must be a regular file")
	}
	b, e := io.ReadAll(io.LimitReader(h, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("input exceeds %d bytes", limit)
	}
	return b, nil
}

// Directory creates each missing directory without following any symlink.
func Directory(path string) error {
	p, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer func() { _ = unix.Close(fd) }()
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(e, unix.ENOENT) {
			if e = unix.Mkdirat(fd, part, 0700); e != nil && !errors.Is(e, unix.EEXIST) {
				return e
			}
			next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if e != nil {
			return e
		}
		_ = unix.Close(fd)
		fd = next
	}
	return nil
}
func Lock(path string) (*os.File, error) {
	dir, base, e := parent(path)
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	fd, e := unix.Openat(int(dir.Fd()), base, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	h := os.NewFile(uintptr(fd), path)
	st, e := h.Stat()
	if e != nil || !st.Mode().IsRegular() {
		_ = h.Close()
		return nil, fmt.Errorf("daemon lock must be a regular file")
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		_ = h.Close()
		return nil, fmt.Errorf("another daemon holds this state directory: %w", e)
	}
	return h, nil
}

// CheckSpace is an advisory preflight. Atomic writes still handle ENOSPC because
// other writers can consume space after this check.
func CheckSpace(directory string, required uint64) error {
	absolute, e := filepath.Abs(directory)
	if e != nil {
		return e
	}
	dir, e := linux.Open("/", strings.TrimPrefix(absolute, "/"), unix.O_PATH|unix.O_DIRECTORY)
	if e != nil {
		return e
	}
	defer dir.Close()
	var fs unix.Statfs_t
	if e = unix.Fstatfs(int(dir.Fd()), &fs); e != nil {
		return e
	}
	if fs.Bsize <= 0 {
		return fmt.Errorf("filesystem reported an invalid block size")
	}
	block := uint64(fs.Bsize)
	blocks := required / block
	if required%block != 0 {
		blocks++
	}
	if fs.Bavail < blocks {
		return fmt.Errorf("insufficient available disk space for the snapshot and configured reserve: %w", unix.ENOSPC)
	}
	return nil
}
