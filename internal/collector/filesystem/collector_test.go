package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jasonachkar/lasa/internal/config"
)

func TestMetadataOnly(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "sudoers")
	if e := os.WriteFile(p, []byte("DO NOT COLLECT THIS SECRET"), 0666); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(p, 0666); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("/etc/passwd", filepath.Join(root, "escape")); e != nil {
		t.Fatal(e)
	}
	c := config.Default()
	c.Roots = []string{root}
	b := (Collector{Config: c}).Collect(context.Background())
	if len(b.Files) < 2 {
		t.Fatalf("missing files: %+v", b)
	}
	for _, o := range b.Observations {
		if o.Value == "DO NOT COLLECT THIS SECRET" {
			t.Fatal("contents collected")
		}
	}
	if len(b.Diagnostics) == 0 {
		t.Fatal("symlink failure hidden")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b = (Collector{Config: c}).Collect(ctx)
	if b.Coverage.Complete {
		t.Fatal("cancel marked complete")
	}
}
