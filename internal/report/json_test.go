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
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<20 {
			return
		}
		_, _ = Decode([]byte(s))
	})
}
