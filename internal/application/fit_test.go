package application

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jasonachkar/lasa/internal/collector"
	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/internal/report"
	"github.com/jasonachkar/lasa/internal/rules"
	"github.com/jasonachkar/lasa/rules/builtin"
)

// manyFiles emits n ordinary files plus one world-writable sudoers file that
// a builtin rule reports, using the facts the filesystem collector records.
type manyFiles struct{ n int }

func (manyFiles) Descriptor() collector.Descriptor {
	return collector.Descriptor{ID: "filesystem", Version: "1"}
}
func (m manyFiles) Collect(context.Context) domain.Batch {
	b := collector.Begin("filesystem", "fixture")
	at := time.Unix(0, 0).UTC()
	add := func(path, kind string, writable bool) {
		f := domain.File{ID: domain.Hash("host", path), Path: path, Mode: 0o100644, Kind: kind, ACL: domain.NotObserved, ReadOnly: domain.NotObserved}
		if writable {
			f.Mode = 0o100666
		}
		b.Files = append(b.Files, f)
		b.Coverage.Attempted++
		b.Coverage.Successful++
		for key, value := range map[string]string{"file.kind": kind, "file.write_candidate": fmt.Sprint(writable), "file.metadata": fmt.Sprintf("mode=%#o uid=0 gid=0", f.Mode)} {
			b.Observations = append(b.Observations, domain.Fact(f.ID, key, value, path, "filesystem", domain.Observed, at))
		}
	}
	add("/etc/sudoers.d/writable", "sudoers", true)
	for i := 0; i < m.n; i++ {
		add(fmt.Sprintf("/usr/share/fixture/%05d", i), "other", false)
	}
	collector.Finish(&b)
	return b
}

func TestOversizedScanIsReducedInsteadOfDiscarded(t *testing.T) {
	pack, err := rules.Load(bytes.NewReader(builtin.YAML))
	if err != nil {
		t.Fatal(err)
	}
	stage := func(*domain.Snapshot) []collector.Collector { return []collector.Collector{manyFiles{n: 400}} }
	full, err := (Engine{Host: domain.Host{ID: "host", BootID: "boot"}, Stages: []Stage{stage}, Rules: pack}).Scan(context.Background(), config.Default())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := report.Marshal(full)
	limit := len(raw) / 3

	engine := Engine{Host: domain.Host{ID: "host", BootID: "boot"}, Stages: []Stage{stage}, Rules: pack, ExportLimit: limit}
	s, err := engine.Scan(context.Background(), config.Default())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = report.Marshal(s)
	if len(raw) > limit {
		t.Fatalf("report of %d bytes still exceeds the %d byte limit", len(raw), limit)
	}
	if len(s.Findings) != 1 || s.Findings[0].RuleID != "LASA-009" {
		t.Fatalf("findings must survive scope reduction: %+v", s.Findings)
	}
	if s.Complete || len(s.Files) >= 401 {
		t.Fatal("a reduced scope must be smaller and reported as incomplete")
	}
	var fs domain.Coverage
	for _, c := range s.Coverage {
		if c.Collector == "filesystem" {
			fs = c
		}
	}
	if fs.Complete || fs.Skipped != 401-len(s.Files) {
		t.Fatalf("omitted files must be counted as skipped: %+v", fs)
	}
	found := false
	for _, d := range s.Diagnostics {
		found = found || d.Code == "RESOURCE_LIMIT" && d.Operation == "fit_export" && strings.Contains(d.Cause, "of 401 file metadata entries")
	}
	if !found {
		t.Fatal("scope reduction must be explained by a diagnostic")
	}
	if _, err = report.Decode(raw); err != nil {
		t.Fatalf("reduced report must remain internally consistent: %v", err)
	}
}

func TestReportWithinLimitIsUnchanged(t *testing.T) {
	stage := func(*domain.Snapshot) []collector.Collector { return []collector.Collector{manyFiles{n: 10}} }
	s, err := (Engine{Host: domain.Host{ID: "host", BootID: "boot"}, Stages: []Stage{stage}}).Scan(context.Background(), config.Default())
	if err != nil || len(s.Files) != 11 || !s.Complete {
		t.Fatalf("scan within the limit must keep its full scope: files=%d complete=%t err=%v", len(s.Files), s.Complete, err)
	}
}
