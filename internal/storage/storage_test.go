package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicPrivate(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "report.json")
	if e := Atomic(p, []byte("one")); e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(p)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("mode: %v %v", st, e)
	}
	if e := Atomic(p, []byte("two")); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "two" {
		t.Fatal("replace failed")
	}
	target := filepath.Join(dir, "target")
	if e := os.WriteFile(target, []byte("secret"), 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "link")
	if e := os.Symlink(target, link); e != nil {
		t.Fatal(e)
	}
	if e := Atomic(link, []byte("bad")); e == nil {
		t.Fatal("symlink output allowed")
	}
	if _, e := Read(link, 100); e == nil {
		t.Fatal("symlink input allowed")
	}
	if e := os.Symlink(dir, filepath.Join(dir, "parent")); e != nil {
		t.Fatal(e)
	}
	if e := Atomic(filepath.Join(dir, "parent", "x"), nil); e == nil {
		t.Fatal("parent symlink allowed")
	}
}
func TestReadLimit(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "x")
	if e := Atomic(p, []byte("1234")); e != nil {
		t.Fatal(e)
	}
	if _, e := Read(p, 3); e == nil {
		t.Fatal("oversize input accepted")
	}
}

func TestOutputOwnerTrust(t *testing.T) {
	for _, tc := range []struct {
		owner   uint32
		euid    int
		sudoUID string
		want    bool
	}{
		{1000, 1000, "", true},   // own directory
		{0, 1000, "", true},      // root-owned directory
		{1001, 1000, "", false},  // another user's directory
		{1000, 0, "1000", true},  // sudo scan into the invoking user's directory
		{1001, 0, "1000", false}, // sudo scan into a third user's directory
		{1000, 0, "", false},     // root without sudo context
		{1000, 0, "not-a-uid", false},
		{1000, 1001, "1000", false}, // SUDO_UID is ignored unless running as root
	} {
		if got := ownerAllowed(tc.owner, tc.euid, tc.sudoUID); got != tc.want {
			t.Errorf("%+v: got %t", tc, got)
		}
	}
}
