package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestRetentionOnlyManagedRegularFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 1; i <= 3; i++ {
		name := fmt.Sprintf("scan-20261018T00000%d.000000000Z-%032x.json", i, i)
		if e := Atomic(filepath.Join(dir, name), []byte("{}")); e != nil {
			t.Fatal(e)
		}
	}
	unrelated := filepath.Join(dir, "keep.json")
	if e := Atomic(unrelated, []byte("private")); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "scan-20261018T000000.000000000Z-00000000000000000000000000000000.json")
	if e := os.Symlink(unrelated, link); e != nil {
		t.Fatal(e)
	}
	if e := Prune(dir, 1); e != nil {
		t.Fatal(e)
	}
	names, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	if len(names) != 3 {
		t.Fatalf("retention touched unrelated files or failed: %v", names)
	}
	b, e := os.ReadFile(unrelated)
	if e != nil || string(b) != "private" {
		t.Fatal("unrelated file altered")
	}
}
func TestUnsafeSharedParent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(dir, 0777); e != nil {
		t.Fatal(e)
	}
	if e := Atomic(filepath.Join(dir, "report"), []byte("private")); e == nil {
		t.Fatal("non-sticky shared output directory accepted")
	}
}
