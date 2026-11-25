package linux

import (
	"path/filepath"
	"strconv"
	"strings"
)

// CgroupMemoryLimit returns this process's cgroup v2 memory.max in bytes. It
// reports false when there is no limit, on cgroup v1, or when the limit
// cannot be read. proc and cgroup are readers rooted at /proc and
// /sys/fs/cgroup; pid is this process's ID (/proc/self is a symlink, which
// constrained readers refuse).
func CgroupMemoryLimit(proc, cgroup Reader, pid int) (int64, bool) {
	raw, err := proc.Read(strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		path, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		rel := strings.TrimPrefix(filepath.Clean("/"+path), "/")
		target := "memory.max"
		if rel != "" {
			target = rel + "/memory.max"
		}
		value, err := cgroup.Read(target)
		if err != nil {
			return 0, false
		}
		limit, err := strconv.ParseInt(strings.TrimSpace(string(value)), 10, 64)
		if err != nil || limit <= 0 {
			return 0, false // "max" means unlimited
		}
		return limit, true
	}
	return 0, false
}
