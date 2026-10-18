package graph

import (
	"testing"
	"time"

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
func TestExecutableIdentityAndDeduplicatedProvenance(t *testing.T) {
	s := domain.Snapshot{Host: domain.Host{ID: "h"}, Files: []domain.File{{ID: "file", Path: "/service", Inode: 10, Device: 1}}}
	for _, id := range []string{"p1", "p2"} {
		p := domain.Process{ID: id, StableID: "service", Executable: "/service", ExecutableInode: 10, ExecutableDevice: 1}
		s.Processes = append(s.Processes, p)
		for _, kv := range [][2]string{{"process.identity", id}, {"identity.euid", "0"}, {"process.executable", "/service"}, {"process.executable_inode", "1:10"}, {"privilege.host_root", "true"}} {
			s.Observations = append(s.Observations, domain.Fact(id, kv[0], kv[1], "fixture", "test", domain.Observed, time.Unix(0, 0)))
		}
	}
	s.Observations = append(s.Observations, domain.Fact("file", "file.metadata", "inode10", "fixture", "test", domain.Observed, time.Unix(0, 0)))
	g, e := Build(&s)
	if e != nil {
		t.Fatal(e)
	}
	executes := 0
	for _, edge := range g.Export().Edges {
		if edge.Type == "EXECUTES" && edge.To == "file" {
			executes++
		}
	}
	if executes != 2 {
		t.Fatal("matching executable inodes not linked")
	}
	ids := map[string]bool{}
	for _, o := range s.Observations {
		if ids[o.ID] {
			t.Fatal("duplicate observation after correlation")
		}
		ids[o.ID] = true
	}
	s2 := domain.Snapshot{Host: s.Host, Processes: s.Processes, Files: []domain.File{{ID: "file", Path: "/service", Inode: 11, Device: 1}}, Observations: s.Observations[:11]}
	g, e = Build(&s2)
	if e != nil {
		t.Fatal(e)
	}
	for _, edge := range g.Export().Edges {
		if edge.Type == "EXECUTES" && edge.To == "file" {
			t.Fatal("replaced path treated as running inode")
		}
	}
}
