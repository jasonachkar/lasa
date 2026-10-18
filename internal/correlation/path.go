package correlation

import "github.com/jasonachkar/lasa/internal/domain"

// supportingGraph returns a bounded connected evidence subgraph. Edge directions
// retain their observed meaning; adjacency is not presented as an exploit step.
func supportingGraph(subject string, adj map[string][]domain.Edge, evidence map[string]bool) ([]string, []domain.Edge, bool) {
	type step struct {
		id    string
		depth int
	}
	queue := []step{{subject, 0}}
	seenNodes := map[string]bool{}
	seenEdges := map[string]bool{}
	var nodes []string
	var edges []domain.Edge
	truncated := false
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if seenNodes[current.id] {
			continue
		}
		seenNodes[current.id] = true
		nodes = append(nodes, current.id)
		if current.depth >= 3 {
			continue
		}
		for _, e := range adj[current.id] {
			supported := len(e.Evidence) > 0
			for _, id := range e.Evidence {
				if !evidence[id] {
					supported = false
					break
				}
			}
			if !supported {
				continue
			}
			key := domain.Hash(e.From, e.Type, e.To)
			if seenEdges[key] {
				continue
			}
			if len(edges) >= 64 {
				truncated = true
				continue
			}
			seenEdges[key] = true
			edges = append(edges, e)
			next := e.To
			if next == current.id {
				next = e.From
			}
			if !seenNodes[next] {
				queue = append(queue, step{next, current.depth + 1})
			}
		}
	}
	return nodes, edges, truncated
}
