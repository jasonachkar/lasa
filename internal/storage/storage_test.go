package storage

import (
	"os"
	"path/filepath"
	"strings"
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

func TestPinnedStateAndExclusiveLock(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "new", "state")
	s, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	lock, err := s.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if second, err := s.Lock(); err == nil {
		second.Close()
		t.Fatal("a second daemon obtained the lock")
	}
	if err := s.WriteSnapshot("../escaped.json", nil); err == nil {
		t.Fatal("accepted a snapshot outside the state directory")
	}
	pinned := filepath.Join(base, "pinned")
	if err := os.Rename(path, pinned); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	name := "scan-20261124T000000.000000000Z-" + strings.Repeat("a", 32) + ".json"
	if err := s.WriteSnapshot(name, []byte("snapshot")); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(pinned, name)); err != nil || string(data) != "snapshot" {
		t.Fatalf("snapshot did not stay in the pinned directory: %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(path, name)); !os.IsNotExist(err) {
		t.Fatalf("snapshot appeared in the replacement directory: %v", err)
	}
}
