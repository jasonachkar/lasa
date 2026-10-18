package graph

import (
	"testing"

	"github.com/jasonachkar/lasa/internal/domain"
)

func TestProvenanceAndTraversal(t *testing.T) {
	g := New()
	g.AddNode(domain.Node{ID: "a"})
	g.AddNode(domain.Node{ID: "b"})
	if e := g.AddEdge(domain.Edge{From: "a", To: "b", Type: "X"}, map[string]bool{}); e == nil {
		t.Fatal("missing evidence allowed")
	}
	for _, edge := range []domain.Edge{{From: "a", To: "b", Type: "X", Evidence: []string{"o"}}, {From: "b", To: "a", Type: "X", Evidence: []string{"o"}}} {
		if e := g.AddEdge(edge, map[string]bool{"o": true}); e != nil {
			t.Fatal(e)
		}
	}
	if nodes := g.Walk("a", 5, 10); len(nodes) != 2 {
		t.Fatalf("cycle handling: %v", nodes)
	}
	if nodes := g.Walk("a", 5, 1); len(nodes) != 1 {
		t.Fatal("budget ignored")
	}
}
