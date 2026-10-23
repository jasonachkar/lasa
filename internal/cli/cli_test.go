package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jasonachkar/lasa/internal/advisory"
	"github.com/jasonachkar/lasa/internal/domain"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCommands(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"rules", "list", "--format", "json"}, {"version"}, {"completion", "bash"}} {
		var out, err bytes.Buffer
		cmd := New(&out, &err)
		cmd.SetArgs(args)
		if e := cmd.ExecuteContext(context.Background()); e != nil {
			t.Fatal(e)
		}
		if out.Len() == 0 {
			t.Fatalf("no output for %v", args)
		}
	}
}
func TestInvalidFlags(t *testing.T) {
	for _, args := range [][]string{{"scan", "--workers", "0"}, {"scan", "--format", "wrong"}, {"scan", "--timeout", "0s"}} {
		var out, err bytes.Buffer
		cmd := New(&out, &err)
		cmd.SetArgs(args)
		if e := cmd.ExecuteContext(context.Background()); e == nil {
			t.Fatalf("bad config accepted: %v", args)
		}
	}
}

func TestAdvisoryImportRejectsExpiredInputWithoutReplacingCache(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input.json"), filepath.Join(dir, "cache.json")
	now := time.Now().UTC()
	db := advisory.Database{Schema: advisory.Schema, Source: "authenticated test fixture", FetchedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Records: []advisory.Record{}}
	run := func() error {
		var out, errOut bytes.Buffer
		cmd := New(&out, &errOut)
		cmd.SetArgs([]string{"advisories", "import", "--input", input, "--output", output})
		return cmd.ExecuteContext(context.Background())
	}
	raw, _ := json.Marshal(db)
	if err := os.WriteFile(input, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(output)
	if info.Mode().Perm()&0077 != 0 {
		t.Fatal("cache is publicly readable")
	}
	db.FetchedAt = now.Add(-2 * time.Hour)
	db.ExpiresAt = now.Add(-time.Hour)
	raw, _ = json.Marshal(db)
	if err := os.WriteFile(input, raw, 0600); err != nil {
		t.Fatal(err)
	}
	err = run()
	var diagnostic domain.Diagnostic
	if !errors.As(err, &diagnostic) || diagnostic.Code != "ADVISORY_IMPORT_FAILED" || diagnostic.Target != input {
		t.Fatalf("missing actionable import error: %v", err)
	}
	after, _ := os.ReadFile(output)
	if !bytes.Equal(before, after) {
		t.Fatal("failed import replaced existing cache")
	}
}
