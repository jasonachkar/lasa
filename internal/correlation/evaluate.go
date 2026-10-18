package correlation

import (
	"sort"

	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/internal/rules"
	"github.com/jasonachkar/lasa/internal/scoring"
)

func Evaluate(s *domain.Snapshot, pack []rules.Rule) {
	idx := rules.Index(s.Observations)
	obsByID := map[string]domain.Observation{}
	for _, o := range s.Observations {
		obsByID[o.ID] = o
	}
	nodes := append([]domain.Node(nil), s.Graph.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	findings := map[string]domain.Finding{}
	for _, r := range pack {
		for _, n := range nodes {
			if n.Kind != r.Subject {
				continue
			}
			result := rules.Evaluate(r.When, n.ID, idx)
			if result.State == domain.Observed && !rules.RequirementsSatisfied(r, n.ID, idx) {
				result.State = domain.Unknown
				result.Reason = "required evidence missing or conflicting"
			}
			s.Evaluations = append(s.Evaluations, domain.Evaluation{RuleID: r.ID, Subject: n.ID, State: result.State, Evidence: result.Evidence, Reason: result.Reason})
			if result.State != domain.Observed {
				continue
			}
			ex := domain.UnknownExposure
			isTrue := func(key string) bool {
				c := rules.Condition{Predicate: key, Op: "eq", Value: true}
				return rules.Evaluate(c, n.ID, idx).State == domain.Observed
			}
			if isTrue("network.confirmed") {
				ex = domain.Confirmed
			} else if isTrue("network.potential") {
				ex = domain.Potential
			}
			priv := isTrue("privilege.host_root")
			score, factors := scoring.Score(r.Severity, ex, priv)
			warnings := []string{"Conditional scenario: no vulnerability, successful compromise, or exploitation has been established."}
			if !s.Complete {
				warnings = append(warnings, "Some scan checks were incomplete; consult coverage and diagnostics.")
			}
			if n.Kind == "file" {
				warnings = append(warnings, "Write permission metadata is a candidate; ACLs, group membership, sticky bits, namespace mappings and mount/execution policy can change effective access.")
			}
			if r.Confidence == "medium" {
				warnings = append(warnings, "Heuristic or indirect relationships require independent verification.")
			}
			refs := expand(result.Evidence, obsByID)
			f := domain.Finding{ID: domain.Hash("lasa.finding/v1", s.Host.ID, r.ID, r.Version, n.StableID), RuleID: r.ID, RuleVersion: r.Version, Title: r.Title, Description: r.Description, Subject: n.ID, Subjects: []string{n.ID}, StableSubject: n.StableID, Severity: r.Severity, Confidence: r.Confidence, Exposure: ex, Evidence: refs, Prerequisites: r.Prerequisites, Warnings: warnings, Remediation: r.Remediation, Priority: score, ScoreVersion: scoring.Version, Factors: factors}
			f.Path = domain.AttackPath{ID: domain.Hash(f.ID, "path"), Entities: []string{n.ID}, Evidence: refs, EntryConditions: r.Prerequisites, ConditionalStep: "If an attacker first gains control of this subject, the observed conditions may increase its potential impact.", PotentialImpact: r.Description, Uncertainties: warnings, Factors: factors}
			for _, e := range s.Graph.Edges {
				if e.From == n.ID && containsAll(refs, e.Evidence) {
					f.Path.Edges = append(f.Path.Edges, e)
					f.Path.Entities = append(f.Path.Entities, e.To)
				}
			}
			for _, c := range s.Coverage {
				f.Coverage = append(f.Coverage, c.Collector)
			}
			if prev, ok := findings[f.ID]; ok {
				f.Subjects = unique(append(prev.Subjects, f.Subjects...))
				f.Path.Entities = unique(append(prev.Path.Entities, f.Path.Entities...))
				f.Path.Edges = append(prev.Path.Edges, f.Path.Edges...)
				f.Evidence = unique(append(prev.Evidence, f.Evidence...))
				f.Path.Evidence = f.Evidence
				f.Warnings = unique(append(prev.Warnings, f.Warnings...))
			}
			findings[f.ID] = f
		}
	}
	for _, f := range findings {
		s.Findings = append(s.Findings, f)
	}
	s.Sort()
}
func expand(refs []string, obs map[string]domain.Observation) []string {
	seen := map[string]bool{}
	q := append([]string(nil), refs...)
	var out []string
	for len(q) > 0 && len(out) < 200000 {
		id := q[0]
		q = q[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		o, ok := obs[id]
		if !ok {
			continue
		}
		out = append(out, id)
		q = append(q, o.Evidence...)
	}
	return unique(out)
}
func unique(s []string) []string {
	sort.Strings(s)
	var out []string
	for _, v := range s {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}
func containsAll(all, sub []string) bool {
	m := map[string]bool{}
	for _, x := range all {
		m[x] = true
	}
	for _, x := range sub {
		if !m[x] {
			return false
		}
	}
	return true
}
