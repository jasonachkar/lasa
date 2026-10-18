package application

import (
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
