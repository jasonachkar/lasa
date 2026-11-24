package application

import (
	"fmt"
	"sort"

	"github.com/jasonachkar/lasa/internal/domain"
)

type Drift struct {
	Schema     string           `json:"schema"`
	Previous   string           `json:"previous_scan"`
	Current    string           `json:"current_scan"`
	New        []domain.Finding `json:"new"`
	Continuing []domain.Finding `json:"continuing"`
	Resolved   []domain.Finding `json:"resolved"`
	Changed    []domain.Finding `json:"changed"`
	Unknown    []domain.Finding `json:"unknown"`
	// UnknownReasons explains, per finding fingerprint, why an absent finding
	// could not be classified as resolved.
	UnknownReasons map[string]string `json:"unknown_reasons"`
}

// Diff classifies findings across two snapshots of the same host. A finding
// that disappeared is resolved only when the current snapshot explicitly
// evaluated the same rule on the same stable subject as absent or not
// applicable, using evidence from collectors that completed their declared
// scope. Gaps in unrelated collectors do not block an independently verified
// resolution; lost visibility never becomes a resolution.
func Diff(old, now domain.Snapshot) (Drift, error) {
	d := Drift{Schema: "lasa.diff/v1", Previous: old.ScanID, Current: now.ScanID, New: []domain.Finding{}, Continuing: []domain.Finding{}, Resolved: []domain.Finding{}, Changed: []domain.Finding{}, Unknown: []domain.Finding{}, UnknownReasons: map[string]string{}}
	if old.Host.ID != now.Host.ID {
		return d, fmt.Errorf("cannot compare different host identities")
	}
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
		} else if prev.ScoreVersion != f.ScoreVersion || prev.Priority != f.Priority || prev.Severity != f.Severity || prev.Confidence != f.Confidence || prev.Exposure != f.Exposure || prev.Suppressed != f.Suppressed {
			d.Changed = append(d.Changed, f)
		} else {
			d.Continuing = append(d.Continuing, f)
		}
	}
	stable := map[string]string{}
	for _, n := range now.Graph.Nodes {
		stable[n.ID] = n.StableID
	}
	evals := map[string][]domain.Evaluation{}
	for _, e := range now.Evaluations {
		key := e.RuleID + ":" + stable[e.Subject]
		evals[key] = append(evals[key], e)
	}
	sources := evidenceCollectors(now.Observations)
	complete := map[string]bool{}
	for _, c := range now.Coverage {
		complete[c.Collector] = c.Complete
	}
	for id, f := range before {
		if _, ok := after[id]; ok {
			continue
		}
		reason := resolution(old, now, evals[f.RuleID+":"+f.StableSubject], sources, complete)
		if reason == "" {
			d.Resolved = append(d.Resolved, f)
		} else {
			d.Unknown = append(d.Unknown, f)
			d.UnknownReasons[f.ID] = reason
		}
	}
	for _, list := range [][]domain.Finding{d.New, d.Continuing, d.Resolved, d.Changed, d.Unknown} {
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	}
	return d, nil
}

// resolution returns an empty string when the evaluations establish that a
// finding is resolved, otherwise the reason it remains unknown.
func resolution(old, now domain.Snapshot, evals []domain.Evaluation, sources map[string][]string, complete map[string]bool) string {
	if old.Profile != now.Profile {
		return fmt.Sprintf("scan profile changed from %s to %s", old.Profile, now.Profile)
	}
	if len(evals) == 0 {
		return "the subject was not evaluated in the current scan (removed, renamed or outside the collected scope)"
	}
	for _, e := range evals {
		if e.State != domain.NotObserved && e.State != domain.NotApplicable {
			return "the current evaluation is " + string(e.State) + ": " + e.Reason
		}
	}
	collectors := map[string]bool{}
	for _, e := range evals {
		for _, id := range e.Evidence {
			for _, c := range sources[id] {
				collectors[c] = true
			}
		}
	}
	if len(collectors) == 0 {
		// Without attributable evidence, only a fully complete scan can
		// establish the absence.
		if !now.Complete {
			return "the negative evaluation has no attributable evidence and the current scan is incomplete"
		}
		return ""
	}
	names := make([]string, 0, len(collectors))
	for c := range collectors {
		names = append(names, c)
	}
	sort.Strings(names)
	for _, c := range names {
		if !complete[c] {
			return "the " + c + " collector that supplies this evidence was incomplete"
		}
	}
	return ""
}

// evidenceCollectors maps each observation to the collectors that produced
// it. Derived observations are attributed to the collectors behind their
// supporting evidence, so completeness is checked where facts originate.
func evidenceCollectors(observations []domain.Observation) map[string][]string {
	byID := make(map[string]domain.Observation, len(observations))
	for _, o := range observations {
		byID[o.ID] = o
	}
	memo := map[string][]string{}
	visiting := map[string]bool{}
	var walk func(string) []string
	walk = func(id string) []string {
		if v, ok := memo[id]; ok {
			return v
		}
		o, ok := byID[id]
		if !ok || visiting[id] {
			return nil
		}
		if !o.Derived {
			memo[id] = []string{o.Collector}
			return memo[id]
		}
		visiting[id] = true
		set := map[string]bool{}
		for _, ref := range o.Evidence {
			for _, c := range walk(ref) {
				set[c] = true
			}
		}
		visiting[id] = false
		out := make([]string, 0, len(set))
		for c := range set {
			out = append(out, c)
		}
		sort.Strings(out)
		memo[id] = out
		return out
	}
	out := make(map[string][]string, len(observations))
	for id := range byID {
		out[id] = walk(id)
	}
	return out
}
