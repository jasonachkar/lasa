package cli

import (
	"bytes"
	"context"
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
