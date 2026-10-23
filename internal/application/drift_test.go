package application

import (
	"testing"

	"github.com/jasonachkar/lasa/internal/domain"
)

func TestIncompleteNeverResolves(t *testing.T) {
	old := domain.Snapshot{Host: domain.Host{ID: "h"}, ScopeFingerprint: "fixture", Findings: []domain.Finding{{ID: "a", RuleID: "R", StableSubject: "stable"}}}
	current := domain.Snapshot{Host: old.Host, ScopeFingerprint: "fixture", Complete: false}
	d, e := Diff(old, current)
	if e != nil || len(d.Unknown) != 1 || len(d.Resolved) != 0 {
		t.Fatalf("%+v %v", d, e)
	}
	current.Complete = true
	current.Graph.Nodes = []domain.Node{{ID: "new", StableID: "stable"}}
	current.Evaluations = []domain.Evaluation{{Subject: "new", RuleID: "R", State: domain.NotObserved}}
	d, e = Diff(old, current)
	if e != nil || len(d.Resolved) != 1 {
		t.Fatalf("%+v %v", d, e)
	}
	current.Host.ID = "different"
	if _, e = Diff(old, current); e == nil {
		t.Fatal("unrelated hosts compared")
	}
}

func TestScopeChangeCannotResolveAndEvidenceChangeIsVisible(t *testing.T) {
	old := domain.Snapshot{Host: domain.Host{ID: "h"}, ScopeFingerprint: "full", Findings: []domain.Finding{{ID: "f", RuleID: "R", StableSubject: "subject", Evidence: []string{"before"}}}}
	now := domain.Snapshot{Host: old.Host, Complete: true, ScopeFingerprint: "narrow", Graph: domain.Graph{Nodes: []domain.Node{{ID: "subject", StableID: "subject"}}}, Evaluations: []domain.Evaluation{{RuleID: "R", Subject: "subject", State: domain.NotObserved}}}
	d, e := Diff(old, now)
	if e != nil || len(d.Unknown) != 1 || len(d.Resolved) != 0 {
		t.Fatalf("narrower scope resolved a finding: %+v %v", d, e)
	}
	now.Findings = []domain.Finding{{ID: "f", RuleID: "R", StableSubject: "subject", Evidence: []string{"after"}}}
	d, e = Diff(old, now)
	if e != nil || len(d.Changed) != 1 {
		t.Fatal("changed evidence was ignored", d, e)
	}
}
func TestSurfaceDriftPreservesMissingVisibility(t *testing.T) {
	old := domain.Snapshot{Host: domain.Host{ID: "h", NetworkNamespace: "net:[1]"}, ScopeFingerprint: "same", Sockets: []domain.Socket{{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Namespace: "net:[1]", State: "listening"}}}
	now := domain.Snapshot{Host: old.Host, ScopeFingerprint: "same", Complete: false}
	d, e := Diff(old, now)
	if e != nil || len(d.SurfaceChanges) != 1 || d.SurfaceChanges[0].State != domain.Unknown {
		t.Fatalf("missing visibility hidden: %+v %v", d, e)
	}
	now.Complete = true
	d, e = Diff(old, now)
	if e != nil || d.SurfaceChanges[0].State != domain.NotObserved {
		t.Fatal("missing listener should be scoped absence, not a safety claim")
	}
}

func TestResolutionUsesActualEvidenceDependencies(t *testing.T) {
	old := domain.Snapshot{Host: domain.Host{ID: "h"}, ScopeFingerprint: "same", Findings: []domain.Finding{{ID: "f", RuleID: "R", StableSubject: "a", Coverage: []string{"inspect.ssh"}}}}
	now := domain.Snapshot{Host: old.Host, ScopeFingerprint: "same", Complete: false, Graph: domain.Graph{Nodes: []domain.Node{{ID: "a", StableID: "a"}}}, Evaluations: []domain.Evaluation{{RuleID: "R", Subject: "a", State: domain.NotObserved}}, Coverage: []domain.Coverage{{Collector: "inspect.ssh", Complete: true}, {Collector: "kernel", Complete: false}}}
	d, e := Diff(old, now)
	if e != nil || len(d.Resolved) != 1 {
		t.Fatal("unrelated kernel visibility blocked independently verified SSH resolution", d, e)
	}
	now.Coverage[0].Complete = false
	d, e = Diff(old, now)
	if e != nil || len(d.Unknown) != 1 {
		t.Fatal("dependent visibility loss was mistaken for remediation", d, e)
	}
}

func TestLegacySurfaceAbsenceCannotEstablishResolution(t *testing.T) {
	old := domain.Snapshot{Host: domain.Host{ID: "h"}, Sockets: []domain.Socket{{Protocol: "tcp", Address: "0.0.0.0", Port: 22, State: "listening"}}}
	now := domain.Snapshot{Host: old.Host, Complete: true}
	d, err := Diff(old, now)
	if err != nil || len(d.SurfaceChanges) != 1 || d.SurfaceChanges[0].State != domain.Unknown {
		t.Fatalf("legacy scope absence was interpreted as verified absence: %+v %v", d, err)
	}
}
