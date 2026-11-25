package report

import (
	"testing"
	"time"

	"github.com/jasonachkar/lasa/internal/domain"
)

func TestSizeMatchesMarshalExactly(t *testing.T) {
	hostile := "<script>& \xff\"\\\n\x1b"
	snapshots := []domain.Snapshot{
		{Schema: domain.SchemaVersion, ScanID: "s", Host: domain.Host{ID: "h"}},
		{Schema: domain.SchemaVersion, ScanID: hostile, Started: time.Unix(1, 5).UTC(), Host: domain.Host{ID: "h", Scope: hostile},
			Processes:    []domain.Process{{ID: "p", Name: hostile, Capabilities: map[string]uint64{"CapEff": 1}, Namespaces: map[string]string{"pid": hostile}}},
			Files:        []domain.File{{ID: "f", Path: "/etc/" + hostile, Mode: 0o100666}, {ID: "g", Path: "/x"}},
			Observations: []domain.Observation{{ID: "o", Subject: "f", Key: "k", Value: hostile, Evidence: []string{"a", "b"}}},
			Findings:     []domain.Finding{{ID: "x", Severity: "high", Warnings: []string{hostile}}},
			Graph:        domain.Graph{Nodes: []domain.Node{{ID: "f", Label: hostile}}},
			Diagnostics:  []domain.Diagnostic{{Code: "C", Cause: hostile}},
			Complete:     true},
	}
	for i, s := range snapshots {
		s.Sort()
		raw, err := Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		size, err := Size(s)
		if err != nil || size != len(raw) {
			t.Fatalf("snapshot %d: Size=%d, len(Marshal)=%d, err=%v", i, size, len(raw), err)
		}
	}
}
