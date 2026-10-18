package process

import (
	"strings"
	"testing"
)

func TestStat(t *testing.T) {
	line := "42 (name ) with spaces) S 1 " + strings.Repeat("0 ", 17) + "123 0"
	pid, ppid, start, e := ParseStat([]byte(line))
	if e != nil || pid != 42 || ppid != 1 || start != 123 {
		t.Fatalf("%d %d %d %v", pid, ppid, start, e)
	}
	for _, s := range []string{"", "1 (x) S", "a (x) S 1", "1 x S 1"} {
		if _, _, _, e := ParseStat([]byte(s)); e == nil {
			t.Fatal("malformed stat accepted")
		}
	}
}
func TestStatus(t *testing.T) {
	s := "Name:\ttest\nUid:\t1 2 3 4\nGid:\t5 6 7 8\nGroups:\t1 2\nCapEff:\t0000000000000001\nNoNewPrivs:\t1\nSeccomp:\t2\n"
	p, e := ParseStatus([]byte(s))
	if e != nil || p.Identity.UID[1] != 2 || p.Capabilities["CapEff"] != 1 || p.Seccomp != 2 {
		t.Fatalf("%+v %v", p, e)
	}
	if _, e := ParseStatus([]byte("Uid: 1 2")); e == nil {
		t.Fatal("truncation accepted")
	}
	if _, e := ParseStatus([]byte("Uid: -1 0 0 0\nGid: 0 0 0 0")); e == nil {
		t.Fatal("negative uid accepted")
	}
}
func FuzzStat(f *testing.F) {
	f.Add("1 (init) S 0 " + strings.Repeat("0 ", 18))
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<20 {
			return
		}
		_, _, _, _ = ParseStat([]byte(s))
	})
}
func FuzzStatus(f *testing.F) {
	f.Add("Uid: 0 0 0 0\nGid: 0 0 0 0\n")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<20 {
			return
		}
		_, _ = ParseStatus([]byte(s))
	})
}
