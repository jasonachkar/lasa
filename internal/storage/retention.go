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

func Prune(path string, keep int) error { return PruneLimits(path, keep, 0) }

func PruneLimits(path string, keep int, byteLimit uint64) error {
	if keep < 1 {
		return fmt.Errorf("retention must be positive")
	}
	p, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	h, e := linux.Open("/", strings.TrimPrefix(p, "/"), unix.O_RDONLY|unix.O_DIRECTORY)
	if e != nil {
		return e
	}
	defer h.Close()
	names, e := h.Readdirnames(20001)
	if e != nil && !errors.Is(e, io.EOF) {
		return e
	}
	if len(names) > 20000 {
		return fmt.Errorf("state directory entry budget exceeded")
	}
	var managed []string
	sizes := map[string]uint64{}
	var total uint64
	for _, name := range names {
		if !snapshotName.MatchString(name) {
			continue
		}
		var st unix.Stat_t
		if e = unix.Fstatat(int(h.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
			return e
		}
		if st.Mode&unix.S_IFMT == unix.S_IFREG && st.Uid == uint32(os.Geteuid()) {
			if st.Size < 0 || uint64(st.Size) > ^uint64(0)-total {
				return fmt.Errorf("invalid or overflowing retained snapshot size")
			}
			sizes[name] = uint64(st.Size)
			total += uint64(st.Size)
			managed = append(managed, name)
		}
	}
	sort.Strings(managed)
	if byteLimit > 0 && len(managed) > 0 && sizes[managed[len(managed)-1]] > byteLimit {
		return fmt.Errorf("newest snapshot alone exceeds --retention-bytes; increase the quota or reduce scan scope; no snapshots were pruned")
	}
	for len(managed) > keep || byteLimit > 0 && total > byteLimit && len(managed) > 1 {
		if e = unix.Unlinkat(int(h.Fd()), managed[0], 0); e != nil {
			return e
		}
		total -= sizes[managed[0]]
		managed = managed[1:]
	}
	return h.Sync()
}
