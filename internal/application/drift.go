package application

import (
	"fmt"
	"sort"

	"github.com/jasonachkar/lasa/internal/domain"
)

type Drift struct {
	SurfaceChanges   []SurfaceChange  `json:"surface_changes,omitempty"`
	ChangesTruncated bool             `json:"changes_truncated"`
	Schema           string           `json:"schema"`
	Previous         string           `json:"previous_scan"`
	Current          string           `json:"current_scan"`
	New              []domain.Finding `json:"new"`
	Continuing       []domain.Finding `json:"continuing"`
	Resolved         []domain.Finding `json:"resolved"`
	Changed          []domain.Finding `json:"changed"`
	Unknown          []domain.Finding `json:"unknown"`
}

func Diff(old, now domain.Snapshot) (Drift, error) {
	d := Drift{Schema: "lasa.diff/v2", Previous: old.ScanID, Current: now.ScanID}
	if old.Host.ID != now.Host.ID {
		return d, fmt.Errorf("cannot compare different host identities")
	}
	d.SurfaceChanges, d.ChangesTruncated = surfaceChanges(old, now)
	before := map[string]domain.Finding{}
	after := map[string]domain.Finding{}
	for _, f := range old.Findings {
		before[f.ID] = f
	}
	for _, f := range now.Findings {
		after[f.ID] = f
		prev, ok := before[f.ID]
		if !ok {
			d.New = append(d.New, f)
		} else if prev.ScoreVersion != f.ScoreVersion || prev.Priority != f.Priority || prev.Severity != f.Severity || prev.Confidence != f.Confidence || prev.Exposure != f.Exposure || prev.Suppressed != f.Suppressed || canonicalEvidence(prev.Evidence) != canonicalEvidence(f.Evidence) {
			d.Changed = append(d.Changed, f)
		} else {
			d.Continuing = append(d.Continuing, f)
		}
	}
	stable := map[string]string{}
	for _, n := range now.Graph.Nodes {
		stable[n.ID] = n.StableID
	}
	evals := map[string][]domain.State{}
	for _, e := range now.Evaluations {
		key := e.RuleID + ":" + stable[e.Subject]
		evals[key] = append(evals[key], e.State)
	}
	for id, f := range before {
		if _, ok := after[id]; ok {
			continue
		}
		states := evals[f.RuleID+":"+f.StableSubject]
		verifiedAbsent := len(states) > 0
		for _, s := range states {
			if s != domain.NotObserved && s != domain.NotApplicable {
				verifiedAbsent = false
			}
		}
		if old.Profile != now.Profile || old.ScopeFingerprint == "" || now.ScopeFingerprint == "" || old.ScopeFingerprint != now.ScopeFingerprint || !findingCoverageComplete(f, now) || !verifiedAbsent {
			d.Unknown = append(d.Unknown, f)
		} else {
			d.Resolved = append(d.Resolved, f)
		}
	}
	for _, list := range [][]domain.Finding{d.New, d.Continuing, d.Resolved, d.Changed, d.Unknown} {
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	}
	return d, nil
}

func findingCoverageComplete(f domain.Finding, s domain.Snapshot) bool {
	if len(f.Coverage) == 0 {
		return s.Complete
	}
	current := map[string]bool{}
	for _, c := range s.Coverage {
		current[c.Collector] = c.Complete
	}
	for _, name := range f.Coverage {
		if !current[name] {
			return false
		}
	}
	return true
}
