package application

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jasonachkar/lasa/internal/domain"
)

func TestIncompleteNeverResolves(t *testing.T) {
	old := domain.Snapshot{Host: domain.Host{ID: "h"}, Findings: []domain.Finding{{ID: "a", RuleID: "R", StableSubject: "stable"}}}
	current := domain.Snapshot{Host: old.Host, Complete: false}
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

// fileResolution builds a current snapshot in which a file rule was evaluated
// negatively from filesystem evidence, with the given collector coverage.
func fileResolution(filesystemComplete, kernelComplete bool, state domain.State) (domain.Snapshot, domain.Snapshot) {
	old := domain.Snapshot{Host: domain.Host{ID: "h"}, Profile: "standard", Findings: []domain.Finding{{ID: "f1", RuleID: "LASA-008", StableSubject: "stable-file"}}}
	now := domain.Snapshot{Host: old.Host, Profile: "standard", Complete: filesystemComplete && kernelComplete,
		Graph:        domain.Graph{Nodes: []domain.Node{{ID: "file-now", StableID: "stable-file"}}},
		Observations: []domain.Observation{{ID: "o1", Subject: "file-now", Key: "file.write_candidate", Value: "false", State: domain.Observed, Collector: "filesystem"}},
		Evaluations:  []domain.Evaluation{{RuleID: "LASA-008", Subject: "file-now", State: state, Evidence: []string{"o1"}}},
		Coverage: []domain.Coverage{
			{Collector: "filesystem", Complete: filesystemComplete},
			{Collector: "kernel", Complete: kernelComplete},
			{Collector: "process", Complete: false},
		}}
	return old, now
}

func TestUnrelatedCollectorGapsDoNotBlockVerifiedResolution(t *testing.T) {
	old, now := fileResolution(true, false, domain.NotObserved)
	d, e := Diff(old, now)
	if e != nil || len(d.Resolved) != 1 || len(d.Unknown) != 0 {
		t.Fatalf("a fix verified by a complete filesystem collector must resolve despite kernel/process gaps: %+v %v", d, e)
	}
}

func TestResolutionRequiresCompleteEvidenceCollectorsAndExplainsUnknowns(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*domain.Snapshot, *domain.Snapshot)
		reason string
	}{
		"evidence collector incomplete": {func(_, now *domain.Snapshot) { now.Coverage[0].Complete = false }, "filesystem collector"},
		"evaluation unknown":            {func(_, now *domain.Snapshot) { now.Evaluations[0].State = domain.Unknown }, "evaluation is unknown"},
		"subject not evaluated":         {func(_, now *domain.Snapshot) { now.Evaluations = nil }, "not evaluated"},
		"profile changed":               {func(old, _ *domain.Snapshot) { old.Profile = "deep" }, "profile changed"},
	} {
		t.Run(name, func(t *testing.T) {
			old, now := fileResolution(true, true, domain.NotObserved)
			tc.mutate(&old, &now)
			d, e := Diff(old, now)
			if e != nil || len(d.Resolved) != 0 || len(d.Unknown) != 1 {
				t.Fatalf("%+v %v", d, e)
			}
			if got := d.UnknownReasons["f1"]; !strings.Contains(got, tc.reason) {
				t.Fatalf("reason %q does not explain %q", got, tc.reason)
			}
		})
	}
}

func TestDerivedEvidenceIsAttributedToItsSourceCollectors(t *testing.T) {
	old, now := fileResolution(true, true, domain.NotObserved)
	now.Observations = append(now.Observations, domain.Observation{ID: "d1", Subject: "file-now", Key: "file.unsafe_parent", State: domain.Observed, Collector: "graph", Derived: true, Evidence: []string{"p1"}},
		domain.Observation{ID: "p1", Subject: "parent", Key: "file.metadata", State: domain.Observed, Collector: "identity"})
	now.Evaluations[0].Evidence = []string{"d1"}
	now.Coverage = append(now.Coverage, domain.Coverage{Collector: "identity", Complete: false})
	d, _ := Diff(old, now)
	if len(d.Resolved) != 0 || !strings.Contains(d.UnknownReasons["f1"], "identity") {
		t.Fatalf("derived evidence must inherit the completeness of its sources: %+v", d)
	}
}

func TestDiffCategoriesAreNeverNull(t *testing.T) {
	d, e := Diff(domain.Snapshot{Host: domain.Host{ID: "h"}}, domain.Snapshot{Host: domain.Host{ID: "h"}})
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(d)
	if bytes.Contains(raw, []byte("null")) {
		t.Fatalf("empty diff categories must serialize as []: %s", raw)
	}
}
