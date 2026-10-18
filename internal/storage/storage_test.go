package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicPrivate(t *testing.T) {
	dir := t.TempDir()
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
	p := filepath.Join(t.TempDir(), "x")
	if e := Atomic(p, []byte("1234")); e != nil {
		t.Fatal(e)
	}
	if _, e := Read(p, 3); e == nil {
		t.Fatal("oversize input accepted")
	}
}
