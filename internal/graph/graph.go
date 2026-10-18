// Package graph builds a bounded, indexed, provenance-aware in-memory graph.
package graph

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/jasonachkar/lasa/internal/domain"
)

type Index struct {
	nodes map[string]domain.Node
	out   map[string][]domain.Edge
	edges int
}

func New() *Index                      { return &Index{nodes: map[string]domain.Node{}, out: map[string][]domain.Edge{}} }
func (g *Index) AddNode(n domain.Node) { g.nodes[n.ID] = n }
func (g *Index) AddEdge(e domain.Edge, observations map[string]bool) error {
	if len(e.Evidence) == 0 {
		return fmt.Errorf("edge %s: missing provenance", e.Type)
	}
	if _, ok := g.nodes[e.From]; !ok {
		return fmt.Errorf("unknown source %s", e.From)
	}
	if _, ok := g.nodes[e.To]; !ok {
		return fmt.Errorf("unknown target %s", e.To)
	}
	for _, id := range e.Evidence {
		if !observations[id] {
			return fmt.Errorf("edge references unknown evidence %s", id)
		}
	}
	if g.edges >= 200000 {
		return fmt.Errorf("graph edge budget exceeded")
	}
	g.out[e.From] = append(g.out[e.From], e)
	g.edges++
	return nil
}
func (g *Index) Walk(start string, depth, budget int) []string {
	if budget <= 0 || depth < 0 {
		return nil
	}
	type step struct {
		id string
		d  int
	}
	q := []step{{start, 0}}
	seen := map[string]bool{}
	var out []string
	for len(q) > 0 && len(out) < budget {
		s := q[0]
		q = q[1:]
		if seen[s.id] {
			continue
		}
		if _, ok := g.nodes[s.id]; !ok {
			continue
		}
		seen[s.id] = true
		out = append(out, s.id)
		if s.d >= depth {
			continue
		}
		edges := append([]domain.Edge(nil), g.out[s.id]...)
		sort.Slice(edges, func(i, j int) bool { return edges[i].To < edges[j].To })
		for _, e := range edges {
			if !seen[e.To] {
				q = append(q, step{e.To, s.d + 1})
			}
		}
	}
	return out
}
func (g *Index) Export() domain.Graph {
	out := domain.Graph{}
	for _, n := range g.nodes {
		out.Nodes = append(out.Nodes, n)
	}
	for _, edges := range g.out {
		out.Edges = append(out.Edges, edges...)
	}
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].ID < out.Nodes[j].ID })
	sort.Slice(out.Edges, func(i, j int) bool {
		a, b := out.Edges[i], out.Edges[j]
		return a.From+a.Type+a.To < b.From+b.Type+b.To
	})
	return out
}
func Build(s *domain.Snapshot) (*Index, error) {
	g := New()
	g.AddNode(domain.Node{ID: s.Host.ID, StableID: s.Host.ID, Kind: "host", Label: "visible Linux host scope"})
	facts := map[string]map[string][]domain.Observation{}
	known := map[string]bool{}
	positions := map[string]int{}
	for pos, o := range s.Observations {
		positions[o.ID] = pos
		known[o.ID] = true
		if facts[o.Subject] == nil {
			facts[o.Subject] = map[string][]domain.Observation{}
		}
		facts[o.Subject][o.Key] = append(facts[o.Subject][o.Key], o)
	}
	refs := func(subject, key string) []string {
		var ids []string
		for _, o := range facts[subject][key] {
			if o.State == domain.Observed {
				ids = append(ids, o.ID)
			}
		}
		sort.Strings(ids)
		return ids
	}
	derived := func(subject, key string, value bool, state domain.State, support []string) {
		o := domain.Fact(subject, key, strconv.FormatBool(value), "graph correlation", "graph", state, s.Completed)
		o.Derived = true
		o.Evidence = support
		if pos, ok := positions[o.ID]; ok {
			seen := map[string]bool{}
			for _, id := range append(s.Observations[pos].Evidence, support...) {
				seen[id] = true
			}
			s.Observations[pos].Evidence = nil
			for id := range seen {
				s.Observations[pos].Evidence = append(s.Observations[pos].Evidence, id)
			}
			sort.Strings(s.Observations[pos].Evidence)
			return
		}
		positions[o.ID] = len(s.Observations)
		s.Observations = append(s.Observations, o)
		known[o.ID] = true
		if facts[subject] == nil {
			facts[subject] = map[string][]domain.Observation{}
		}
		facts[subject][key] = append(facts[subject][key], o)
	}
	edge := func(from, to, kind string, ids []string) error {
		return g.AddEdge(domain.Edge{From: from, To: to, Type: kind, Evidence: ids}, known)
	}
	files := map[string]domain.File{}
	for _, f := range s.Files {
		files[f.Path] = f
		g.AddNode(domain.Node{ID: f.ID, StableID: domain.Hash(s.Host.ID, f.Path), Kind: "file", Label: f.Path})
	}
	for _, sock := range s.Sockets {
		g.AddNode(domain.Node{ID: sock.ID, StableID: domain.Hash(s.Host.ID, sock.Protocol, sock.Address, strconv.Itoa(int(sock.Port))), Kind: "socket", Label: sock.Protocol + " " + sock.Address + ":" + strconv.Itoa(int(sock.Port))})
	}
	for _, m := range s.Mounts {
		g.AddNode(domain.Node{ID: m.ID, StableID: domain.Hash(s.Host.ID, m.Target, m.Source), Kind: "mount", Label: m.Target})
	}
	for _, k := range s.Controls {
		g.AddNode(domain.Node{ID: k.ID, StableID: k.ID, Kind: "control", Label: k.Name})
	}
	for _, ct := range s.Containers {
		g.AddNode(domain.Node{ID: ct.ID, StableID: ct.ID, Kind: "container", Label: ct.Hint + " (hint)"})
	}
	for _, svc := range s.Services {
		g.AddNode(domain.Node{ID: svc.ID, StableID: svc.ID, Kind: "service", Label: svc.Name})
	}
	socketsByOwner := map[string][]domain.Socket{}
	for _, sock := range s.Sockets {
		for _, owner := range sock.Owners {
			socketsByOwner[owner] = append(socketsByOwner[owner], sock)
		}
	}
	networkComplete := false
	for _, c := range s.Coverage {
		if c.Collector == "network" {
			networkComplete = c.Complete
		}
	}
	for _, p := range s.Processes {
		g.AddNode(domain.Node{ID: p.ID, StableID: p.StableID, Kind: "process", Label: p.Executable})
		id := domain.Hash(p.Namespaces["user"], strconv.FormatUint(uint64(p.Identity.UID[1]), 10))
		g.AddNode(domain.Node{ID: id, StableID: id, Kind: "identity", Label: "euid " + strconv.FormatUint(uint64(p.Identity.UID[1]), 10)})
		if e := edge(p.ID, id, "RUNS_AS", refs(p.ID, "identity.euid")); e != nil {
			return nil, e
		}
		for ns, val := range p.Namespaces {
			nid := domain.Hash(ns, val)
			g.AddNode(domain.Node{ID: nid, StableID: nid, Kind: "namespace", Label: val})
			if e := edge(p.ID, nid, "IN_NAMESPACE", refs(p.ID, "namespace."+ns)); e != nil {
				return nil, e
			}
		}
		var potential, management bool
		var supports []string
		for _, sock := range socketsByOwner[p.ID] {
			ids := append(refs(p.ID, "process.identity"), refs(sock.ID, "socket.endpoint")...)
			supports = append(supports, ids...)
			kind := "HOLDS_SOCKET"
			if sock.Protocol != "unix" {
				kind = "LISTENS_ON"
				if sock.Exposure == domain.Potential {
					potential = true
					switch sock.Port {
					case 22, 2375, 2376, 3389, 5432, 6379, 6443, 9200, 10250, 27017:
						management = true
					}
				}
			}
			if e := edge(p.ID, sock.ID, kind, ids); e != nil {
				return nil, e
			}
		}
		st := domain.Observed
		if !networkComplete || !p.FDComplete {
			st = domain.Unknown
		}
		if potential {
			derived(p.ID, "network.potential", true, domain.Observed, supports)
		} else {
			derived(p.ID, "network.potential", false, st, append(supports, refs(p.ID, "descriptor.complete")...))
		}
		if management {
			derived(p.ID, "network.management", true, domain.Observed, supports)
		} else {
			derived(p.ID, "network.management", false, st, supports)
		}
		derived(p.ID, "network.confirmed", false, domain.Unknown, nil)
		derived(p.ID, "container.host_pid", p.Namespaces["pid"] == "pid:[4026531836]", state(p.Namespaces["pid"] != ""), refs(p.ID, "namespace.pid"))
		for _, ct := range s.Containers {
			if ct.Process == p.ID {
				if e := edge(p.ID, ct.ID, "BELONGS_TO_CONTAINER", refs(p.ID, "container.hint")); e != nil {
					return nil, e
				}
			}
		}
		if p.Executable != "" && p.ExecutableInode != 0 {
			xid := domain.Hash(s.Host.ID, "executable", p.Executable, fmt.Sprint(p.ExecutableDevice, p.ExecutableInode))
			g.AddNode(domain.Node{ID: xid, StableID: domain.Hash(s.Host.ID, p.Executable), Kind: "executable", Label: p.Executable})
			if e := edge(p.ID, xid, "EXECUTES", refs(p.ID, "process.executable_inode")); e != nil {
				return nil, e
			}
		}
		if cap, ok := p.Capabilities["CapEff"]; ok {
			for bit := 0; bit < 64; bit++ {
				if cap&(uint64(1)<<bit) == 0 {
					continue
				}
				cid := domain.Hash(p.Namespaces["user"], "capability", strconv.Itoa(bit))
				g.AddNode(domain.Node{ID: cid, StableID: cid, Kind: "capability", Label: fmt.Sprintf("effective capability %d in %s", bit, p.Namespaces["user"])})
				if e := edge(p.ID, cid, "HAS_CAPABILITY", refs(p.ID, "capability.mask")); e != nil {
					return nil, e
				}
			}
		}
		for _, control := range []struct {
			key     string
			enabled bool
		}{{"isolation.seccomp", p.Seccomp > 0}, {"isolation.no_new_privs", p.NoNewPrivs == 1}} {
			if control.enabled {
				id := domain.Hash(p.ID, control.key)
				g.AddNode(domain.Node{ID: id, StableID: domain.Hash(p.StableID, control.key), Kind: "control", Label: control.key + " configured (effectiveness not proven)"})
				if e := edge(p.ID, id, "PROTECTED_BY", refs(p.ID, control.key)); e != nil {
					return nil, e
				}
			}
		}
		if f, ok := files[p.Executable]; ok {
			ids := append(refs(p.ID, "process.executable_inode"), refs(f.ID, "file.metadata")...)
			if p.ExecutableInode == f.Inode && p.ExecutableDevice == f.Device && p.ExecutableInode != 0 {
				if e := edge(p.ID, f.ID, "EXECUTES", ids); e != nil {
					return nil, e
				}
				priv := false
				for _, o := range facts[p.ID]["privilege.host_root"] {
					priv = priv || o.State == domain.Observed && o.Value == "true"
				}
				if priv {
					derived(f.ID, "file.privileged_execution", true, domain.Observed, append(ids, refs(p.ID, "privilege.host_root")...))
				}
			}
		}

		sensitive := false
		var mountrefs []string
		mountKnown := false
		for _, m := range s.Mounts {
			if m.Namespace != p.Namespaces["mnt"] {
				continue
			}
			mountKnown = true
			if strings.HasPrefix(m.Target, "/host/") && (strings.Contains(m.Target, "/etc") || strings.Contains(m.Target, "/proc") || strings.Contains(m.Target, "/sys")) {
				sensitive = true
				mountrefs = append(mountrefs, refs(m.ID, "mount.options")...)
				if e := edge(p.ID, m.ID, "MOUNTS", refs(m.ID, "mount.options")); e != nil {
					return nil, e
				}
			}
		}
		derived(p.ID, "container.sensitive_mount", sensitive, state(mountKnown), mountrefs)
	}
	representatives := map[string]domain.Process{}
	ps := append([]domain.Process(nil), s.Processes...)
	sort.Slice(ps, func(i, j int) bool { return ps[i].ID < ps[j].ID })
	for _, p := range ps {
		keys := make([]string, 0, len(p.Namespaces))
		for k := range p.Namespaces {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, ns := range keys {
			val := p.Namespaces[ns]
			key := ns + val
			if rep, ok := representatives[key]; ok {
				ids := append(refs(p.ID, "namespace."+ns), refs(rep.ID, "namespace."+ns)...)
				if e := edge(p.ID, rep.ID, "SHARES_NAMESPACE_WITH", ids); e != nil {
					return nil, e
				}
			} else {
				representatives[key] = p
			}
		}
	}

	for _, f := range s.Files {
		writableParent := false
		var ids []string
		for path := filepath.Dir(f.Path); path != "/" && path != "."; path = filepath.Dir(path) {
			if parent, ok := files[path]; ok && (parent.Mode&0002 != 0 || parent.Mode&0020 != 0 && parent.GID != 0) && parent.ReadOnly != domain.Observed {
				writableParent = true
				ids = append(ids, refs(parent.ID, "file.metadata")...)
			}
		}
		derived(f.ID, "file.unsafe_parent", writableParent, func() domain.State {
			if writableParent {
				return domain.Observed
			}
			return domain.Unknown
		}(), ids)
	}
	s.Graph = g.Export()
	return g, nil
}
func state(ok bool) domain.State {
	if ok {
		return domain.Observed
	}
	return domain.Unknown
}
