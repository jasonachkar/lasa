//go:build linux

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jasonachkar/lasa/internal/domain"
)

var binary string

func TestMain(m *testing.M) {
	dir, e := os.MkdirTemp("", "lasa-e2e-")
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	binary = filepath.Join(dir, "lasa")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/lasa")
	if out, e := build.CombinedOutput(); e != nil {
		fmt.Fprintln(os.Stderr, string(out), e)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
func run(t *testing.T, args ...string) ([]byte, []byte, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, binary, args...)
	var out, stderr bytes.Buffer
	c.Stdout = &out
	c.Stderr = &stderr
	e := c.Run()
	code := 0
	if e != nil {
		var exit *exec.ExitError
		if !errors.As(e, &exit) {
			t.Fatal(e)
		}
		code = exit.ExitCode()
	}
	return out.Bytes(), stderr.Bytes(), code
}
func TestScanRenderExplainAndExitCodes(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// An image-style layout: sudoers configuration is recognized by location.
	if e := os.MkdirAll(filepath.Join(dir, "image", "etc", "sudoers.d"), 0700); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "image", "etc", "sudoers.d", "admins")
	if e := os.WriteFile(p, []byte("never read these contents"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(p, 0666); e != nil {
		t.Fatal(e)
	}
	report := filepath.Join(dir, "scan.json")
	_, stderr, code := run(t, "scan", "--roots", p, "--fail-on", "high", "--format", "json", "--output", report)
	if code != 1 || len(stderr) != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	raw, e := os.ReadFile(report)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("never read these contents")) {
		t.Fatal("file contents leaked")
	}
	var s domain.Snapshot
	if e = json.Unmarshal(raw, &s); e != nil {
		t.Fatal(e)
	}
	var id string
	for _, f := range s.Findings {
		if f.RuleID == "LASA-009" {
			id = f.ID
		}
	}
	if id == "" {
		t.Fatal("unsafe scoped configuration not detected")
	}
	for _, format := range []string{"html", "sarif", "terminal"} {
		out, stderr, code := run(t, "report", "--input", report, "--format", format)
		if code != 0 || len(out) == 0 {
			t.Fatalf("%s: %d %s", format, code, stderr)
		}
	}
	out, stderr, code := run(t, "explain", id, "--report", report, "--format", "json")
	if code != 0 || !bytes.Contains(out, []byte("observations")) {
		t.Fatalf("explain: %d %s", code, stderr)
	}
	out, stderr, code = run(t, "diff", report, report)
	if code != 0 || !bytes.Contains(out, []byte("continuing")) {
		t.Fatalf("diff: %d %s", code, stderr)
	}
	_, stderr, code = run(t, "scan", "--roots", filepath.Join(dir, "absent"), "--strict", "--format", "json", "--output", filepath.Join(dir, "partial.json"))
	if code != 3 {
		t.Fatalf("strict: %d %s", code, stderr)
	}
	_, stderr, code = run(t, "scan", "--workers", "0", "--diagnostics-format", "json")
	if code != 2 || !bytes.Contains(stderr, []byte("CONFIG_INVALID")) {
		t.Fatalf("fatal: %d %s", code, stderr)
	}
}
func TestDaemonSIGTERM(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, binary, "daemon", "--state-dir", dir, "--roots", dir, "--interval", "1s", "--retention", "2")
	var stderr bytes.Buffer
	c.Stderr = &stderr
	if e := c.Start(); e != nil {
		t.Fatal(e)
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		names, e := os.ReadDir(dir)
		if e != nil {
			t.Fatal(e)
		}
		for _, n := range names {
			if strings.HasPrefix(n.Name(), "scan-") {
				found = true
			}
		}
		if found {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !found {
		t.Fatal("no daemon snapshot")
	}
	if e := c.Process.Signal(syscall.SIGTERM); e != nil {
		t.Fatal(e)
	}
	e := c.Wait()
	stopped = true
	if e != nil {
		t.Fatalf("shutdown failed: %v %s", e, stderr.String())
	}
	names, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range names {
		if strings.HasPrefix(n.Name(), "scan-") {
			st, e := os.Stat(filepath.Join(dir, n.Name()))
			if e != nil || st.Mode().Perm() != 0600 {
				t.Fatal("snapshot not private")
			}
		}
	}
}
