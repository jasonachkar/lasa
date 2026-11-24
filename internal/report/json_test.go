package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jasonachkar/lasa/internal/domain"
)

func TestFormatsEscape(t *testing.T) {
	s := domain.Snapshot{Schema: domain.SchemaVersion, ScanID: "id", Host: domain.Host{ID: "host"}, Findings: []domain.Finding{{ID: "finding", Title: "<script>alert(1)</script>\x1b[31m", Severity: "high", Subject: "subject", Path: domain.AttackPath{}}}}
	for _, format := range []string{"terminal", "json", "html", "sarif"} {
		b, e := Render(s, format)
		if e != nil {
			t.Fatal(e)
		}
		if format == "terminal" && bytes.Contains(b, []byte{27}) {
			t.Fatal("terminal escape retained")
		}
		if format == "html" && strings.Contains(string(b), "<script>alert") {
			t.Fatal("HTML injection")
		}
		if format == "sarif" && !strings.Contains(string(b), "2.1.0") {
			t.Fatal("missing SARIF version")
		}
	}
}
func TestDecodeRejects(t *testing.T) {
	for _, b := range []string{"{}", "{\"schema\":\"wrong\"}", "{\"schema\":\"lasa.report/v1\",\"scan_id\":\"x\",\"host\":{\"id\":\"h\"},\"mystery\":1}"} {
		if _, e := Decode([]byte(b)); e == nil {
			t.Fatal("bad report accepted")
		}
	}
}
func FuzzDecode(f *testing.F) {
	f.Add("{}")
	f.Add(`{"schema":"lasa.report/v1","scan_id":"scan","host":{"id":"host"},"observations":[{"id":"o","subject":"host","key":"test","state":"observed"}],"graph":{"nodes":[{"id":"host"}],"edges":[]}}`)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<20 {
			return
		}
		_, _ = Decode([]byte(s))
	})
}
func TestInvalidByteEscaping(t *testing.T) {
	if got := Safe(string([]byte{'a', 0xff, 27})); got != "a\\xff\\x1b" {
		t.Fatalf("unsafe display %q", got)
	}
}
func TestRejectsDanglingGraphAndFinding(t *testing.T) {
	s := domain.Snapshot{Schema: domain.SchemaVersion, ScanID: "id", Host: domain.Host{ID: "h"}, Graph: domain.Graph{Nodes: []domain.Node{{ID: "h"}}}, Findings: []domain.Finding{{ID: "f", Subject: "missing"}}}
	raw, e := Render(s, "json")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(raw); e == nil {
		t.Fatal("dangling finding accepted")
	}
	s.Findings = nil
	s.Graph.Edges = []domain.Edge{{From: "h", To: "missing", Evidence: []string{"o"}}}
	raw, e = Render(s, "json")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(raw); e == nil {
		t.Fatal("dangling graph accepted")
	}
}

func TestDecodeRejectsAmbiguousJSONNames(t *testing.T) {
	for _, raw := range []string{
		`{"schema":"lasa.report/v1","scan_id":"scan","host":{"id":"first","id":"second"}}`,
		`{"schema":"lasa.report/v1","scan_id":"scan","host":{"id":"first","ID":"second"}}`,
		`{"schema":"lasa.report/v1","scan_id":"scan","host":{"id":"first"}} {}`,
	} {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Fatal("ambiguous snapshot accepted")
		}
	}
}
