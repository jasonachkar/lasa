package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
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
