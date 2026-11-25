package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/internal/rules"
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

func TestRuleMetadataCommands(t *testing.T) {
	for _, tc := range []struct {
		command string
		check   func(*testing.T, []byte)
	}{
		{"list", func(t *testing.T, data []byte) {
			var pack rules.Pack
			if err := json.Unmarshal(data, &pack); err != nil || pack.Schema != rules.Schema || len(pack.Rules) == 0 {
				t.Fatalf("invalid rules list: %v", err)
			}
		}},
		{"predicates", func(t *testing.T, data []byte) {
			var predicates []struct{ Name, Subject, Type string }
			if err := json.Unmarshal(data, &predicates); err != nil || len(predicates) == 0 {
				t.Fatalf("invalid predicate inventory: %v", err)
			}
			seen := make(map[string]bool)
			for _, predicate := range predicates {
				if predicate.Name == "" || predicate.Subject == "" || predicate.Type == "" || seen[predicate.Name] {
					t.Fatalf("invalid or duplicate predicate: %+v", predicate)
				}
				seen[predicate.Name] = true
			}
		}},
	} {
		t.Run(tc.command, func(t *testing.T) {
			var out, stderr bytes.Buffer
			cmd := New(&out, &stderr)
			cmd.SetArgs([]string{"rules", tc.command, "--format", "json"})
			if err := cmd.ExecuteContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			if stderr.Len() > 0 {
				t.Fatalf("unexpected stderr: %s", stderr.String())
			}
			tc.check(t, out.Bytes())
		})
	}
}

func TestCommandErrorsAreSpecificAndActionable(t *testing.T) {
	for args, want := range map[string]string{
		"scan --fail-on bogus": `invalid severity "bogus"`,
		"scan --max-files 0":   "--max-files must be between 1 and 100000, got 0",
		"scan --workers 99":    "--workers must be between 1 and 32, got 99",
		"scan --color purple":  `got "purple"`,
		"report --input /nope": "REPORT_READ_FAILED",
		"scan --format yaml":   `unsupported format "yaml"`,
	} {
		var out, errOut bytes.Buffer
		cmd := New(&out, &errOut)
		cmd.SetArgs(strings.Fields(args))
		e := cmd.ExecuteContext(context.Background())
		if e == nil {
			t.Fatalf("%s: accepted", args)
		}
		WriteError(&errOut, e, false)
		text := errOut.String()
		if !strings.Contains(text, want) || !strings.Contains(text, "hint: ") || strings.Contains(text, "impact:") {
			t.Errorf("%s: unhelpful error %q", args, text)
		}
	}
}

func TestFindFindingAcceptsPrefixesAndUniqueRuleIDs(t *testing.T) {
	s := domain.Snapshot{Findings: []domain.Finding{
		{ID: "abcdef0011112222", RuleID: "LASA-009"},
		{ID: "abcdef0099998888", RuleID: "LASA-013"},
		{ID: "1234567890abcdef", RuleID: "LASA-013"},
	}}
	for query, want := range map[string]string{
		"abcdef0011112222": "abcdef0011112222",
		"ABCDEF001":        "abcdef0011112222",
		"123456":           "1234567890abcdef",
		"lasa-009":         "abcdef0011112222",
	} {
		f, e := findFinding(s, query, "r.json")
		if e != nil || f.ID != want {
			t.Errorf("%s: got %q, %v", query, f.ID, e)
		}
	}
	for query, code := range map[string]string{"abcdef": "FINDING_AMBIGUOUS", "LASA-013": "FINDING_AMBIGUOUS", "abc": "FINDING_NOT_FOUND", "ffffff": "FINDING_NOT_FOUND"} {
		_, e := findFinding(s, query, "r.json")
		var d domain.Diagnostic
		if !errors.As(e, &d) || d.Code != code {
			t.Errorf("%s: expected %s, got %v", query, code, e)
		}
	}
}

func TestReportsCanBeReadFromStandardInput(t *testing.T) {
	var out, errOut bytes.Buffer
	cmd := New(&out, &errOut)
	cmd.SetIn(strings.NewReader("{}"))
	cmd.SetArgs([]string{"report", "--input", "-"})
	e := cmd.ExecuteContext(context.Background())
	var d domain.Diagnostic
	if !errors.As(e, &d) || d.Code != "REPORT_INVALID" || d.Target != "standard input" {
		t.Fatalf("standard input must be decoded and validated like a file: %v", e)
	}
	cmd = New(&out, &errOut)
	cmd.SetArgs([]string{"diff", "-", "-"})
	if e = cmd.ExecuteContext(context.Background()); e == nil {
		t.Fatal("both diff inputs cannot come from standard input")
	}
}

func TestClassifyEnvironment(t *testing.T) {
	for _, tc := range []struct {
		release             string
		wsl, docker, podman bool
		want                string
	}{
		{"6.6.87.2-microsoft-standard-WSL2", false, false, false, "WSL2"},
		{"6.8.0-generic", true, false, false, "WSL2"},
		{"4.4.0", false, false, false, "native"},
		{"6.8.0-generic", false, true, false, "container"},
		{"6.8.0-generic", false, false, true, "container"},
		{"6.8.0-generic", false, false, false, "native"},
	} {
		name, _ := classifyEnvironment(tc.release, tc.wsl, tc.docker, tc.podman)
		if !strings.Contains(name, tc.want) {
			t.Errorf("%+v: got %q", tc, name)
		}
	}
}

func TestDoctorReportsOpenat2AndEnvironment(t *testing.T) {
	var out, errOut bytes.Buffer
	cmd := New(&out, &errOut)
	cmd.SetArgs([]string{"doctor", "--format", "json"})
	_ = cmd.ExecuteContext(context.Background())
	for _, want := range []string{`"name": "openat2"`, `"name": "environment"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("doctor output is missing %s", want)
		}
	}
}

func TestDoctorStatesWhatAFailedCheckAffects(t *testing.T) {
	for check, want := range map[string]string{"procfs": "scans cannot run", "ebpf_tracepoints": "only --profile sensor", "mount_visibility": "mount and read-only context"} {
		got := doctorImpact(DoctorCheck{Name: check, Required: check == "procfs"})
		if !strings.Contains(got, want) || strings.Contains(got, "dependent rules") {
			t.Errorf("%s: %q", check, got)
		}
	}
}
