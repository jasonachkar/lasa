package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/diagnostics"
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

func TestPolicyExclusionsAndAbsentRootsKeepCoverageComplete(t *testing.T) {
	root := t.TempDir()
	if e := os.WriteFile(filepath.Join(root, "real"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("/etc/alternatives/awk", filepath.Join(root, "awk")); e != nil {
		t.Fatal(e)
	}
	c := config.Default()
	c.Roots = []string{root, filepath.Join(root, "absent.sock")}
	b := (Collector{Config: c}).Collect(context.Background())
	if !b.Coverage.Complete || b.Coverage.Unsupported != 2 || b.Coverage.Inconclusive != 0 || b.Coverage.Skipped != 0 {
		t.Fatalf("established exclusions must not make coverage incomplete: %+v", b.Coverage)
	}
	codes := map[string]string{}
	for _, d := range b.Diagnostics {
		codes[d.Code] = d.Cause
		if !diagnostics.IsExpected(d.Code) {
			t.Fatalf("unexpected gap diagnostic %+v", d)
		}
	}
	if !strings.Contains(codes[diagnostics.CodeSymlinkNotFollowed], "/etc/alternatives/awk") {
		t.Fatalf("symlink exclusion must record the link target, got %q", codes[diagnostics.CodeSymlinkNotFollowed])
	}
	if _, ok := codes[diagnostics.CodeNotPresent]; !ok {
		t.Fatal("an absent configured root must be recorded")
	}
	for _, f := range b.Files {
		if strings.HasSuffix(f.Path, "/awk") {
			t.Fatal("a symbolic link must not be inspected as a file")
		}
	}
}

func TestRootThroughSymlinkIsAnExplainedGap(t *testing.T) {
	base := t.TempDir()
	if e := os.Mkdir(filepath.Join(base, "real"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("real", filepath.Join(base, "link")); e != nil {
		t.Fatal(e)
	}
	c := config.Default()
	c.Roots = []string{filepath.Join(base, "link", "child")}
	b := (Collector{Config: c}).Collect(context.Background())
	if b.Coverage.Complete || len(b.Diagnostics) != 1 || !strings.Contains(b.Diagnostics[0].Cause, "symbolic link") || !strings.Contains(b.Diagnostics[0].Remediation, "canonical") {
		t.Fatalf("a root that traverses a symlink must stay an explained gap: %+v", b.Diagnostics)
	}
}
