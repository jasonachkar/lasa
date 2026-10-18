package linux

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConstrainedFS(t *testing.T) {
	root := t.TempDir()
	if e := os.WriteFile(filepath.Join(root, "ok"), []byte("metadata"), 0600); e != nil {
		t.Fatal(e)
	}
	fs := FS{Root: root, Limit: 4}
	if _, e := fs.Read("ok"); e == nil {
		t.Fatal("oversize read accepted")
	}
	fs.Limit = 32
	b, e := fs.Read("ok")
	if e != nil || string(b) != "metadata" {
		t.Fatalf("%q %v", b, e)
	}
	for _, p := range []string{"../etc/passwd", "/etc/passwd"} {
		if _, e := fs.Read(p); e == nil {
			t.Fatalf("escape accepted: %s", p)
		}
	}
	if e := os.Symlink("/etc/passwd", filepath.Join(root, "link")); e != nil {
		t.Fatal(e)
	}
	if _, e := fs.Read("link"); e == nil {
		t.Fatal("symlink followed")
	}
}
