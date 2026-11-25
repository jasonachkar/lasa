package linux

import (
	"io/fs"
	"testing"
)

type files map[string]string

func (f files) Read(p string) ([]byte, error) {
	if v, ok := f[p]; ok {
		return []byte(v), nil
	}
	return nil, fs.ErrNotExist
}
func (files) Readlink(string) (string, error)           { return "", fs.ErrNotExist }
func (files) Names(string, int) ([]string, bool, error) { return nil, false, fs.ErrNotExist }

func TestCgroupMemoryLimit(t *testing.T) {
	proc := files{"7/cgroup": "0::/system.slice/lasa.service\n"}
	for value, want := range map[string]int64{"536870912\n": 536870912, "max\n": 0} {
		got, ok := CgroupMemoryLimit(proc, files{"system.slice/lasa.service/memory.max": value}, 7)
		if got != want || ok != (want > 0) {
			t.Errorf("memory.max %q: got %d %t", value, got, ok)
		}
	}
	if _, ok := CgroupMemoryLimit(files{"7/cgroup": "4:memory:/user\n"}, files{}, 7); ok {
		t.Error("cgroup v1 must report no limit")
	}
	if got, ok := CgroupMemoryLimit(files{"7/cgroup": "0::/\n"}, files{"memory.max": "1048576"}, 7); !ok || got != 1048576 {
		t.Errorf("root cgroup: %d %t", got, ok)
	}
}
