package correlation

import (
	"testing"

	"github.com/jasonachkar/lasa/internal/domain"
)

func TestInboundEvidenceAndConditionalBoundaries(t *testing.T) {
	edge := domain.Edge{From: "process", To: "file", Type: "EXECUTES", Evidence: []string{"inode"}}
	other := domain.Edge{From: "process", To: "secret", Type: "CAN_WRITE", Evidence: []string{"unproven"}}
	adj := map[string][]domain.Edge{"file": {edge}, "process": {edge, other}}
	nodes, edges, truncated := supportingGraph("file", adj, map[string]bool{"inode": true})
	if len(nodes) != 2 || len(edges) != 1 || truncated || edges[0].From != "process" {
		t.Fatalf("lost inbound evidence or invented access: %v %v", nodes, edges)
	}
}
