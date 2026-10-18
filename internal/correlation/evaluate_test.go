package correlation

import (
	"bytes"
	"testing"
	"time"

	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/internal/rules"
	"github.com/jasonachkar/lasa/rules/builtin"
)

func TestFingerprintsAndEvidence(t *testing.T) {
	pack, e := rules.Load(bytes.NewReader(builtin.YAML))
	if e != nil {
		t.Fatal(e)
	}
	scan := func(scan, pid string) domain.Snapshot {
		s := domain.Snapshot{Host: domain.Host{ID: "host"}, ScanID: scan, Complete: true, Graph: domain.Graph{Nodes: []domain.Node{{ID: pid, StableID: "sshd.service", Kind: "process"}}}}
		for _, k := range []string{"network.potential", "capability.dangerous", "privilege.host_root", "isolation.weak"} {
			s.Observations = append(s.Observations, domain.Fact(pid, k, "true", "fixture", "test", domain.Observed, time.Now()))
		}
		Evaluate(&s, pack)
		return s
	}
	a, b := scan("one", "pid1"), scan("two", "pid2")
	if len(a.Findings) == 0 || len(a.Findings) != len(b.Findings) {
		t.Fatal("no genuine correlation")
	}
	for i, f := range a.Findings {
		if f.ID != b.Findings[i].ID || len(f.Evidence) == 0 || f.Path.ConditionalStep == "" {
			t.Fatalf("identity/provenance failure: %+v", f)
		}
	}
}
