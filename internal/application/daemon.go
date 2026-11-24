package application

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/internal/report"
	"github.com/jasonachkar/lasa/internal/storage"
)

type Daemon struct {
	Directory string
	Interval  time.Duration
	Retention int
	Scan      func(context.Context) (domain.Snapshot, error)
	Log       io.Writer
}

// baseline is the part of the previous snapshot that change logging needs.
// It is kept instead of the full snapshot to bound daemon memory.
type baseline struct {
	snapshot domain.Snapshot
	labels   map[string]string
}

func newBaseline(s domain.Snapshot) *baseline {
	b := &baseline{snapshot: domain.Snapshot{ScanID: s.ScanID, Profile: s.Profile, Host: s.Host, Findings: s.Findings}, labels: map[string]string{}}
	for _, n := range s.Graph.Nodes {
		b.labels[n.ID] = n.Label
	}
	return b
}

func (d Daemon) Run(ctx context.Context) error {
	if d.Interval < time.Second {
		return fmt.Errorf("--interval must be at least 1s, got %s", d.Interval)
	}
	if d.Retention < 1 || d.Retention > 10000 {
		return fmt.Errorf("--retention must be between 1 and 10000, got %d", d.Retention)
	}
	if d.Scan == nil {
		return fmt.Errorf("daemon requires a scanner")
	}
	state, e := storage.OpenState(d.Directory)
	if e != nil {
		return fmt.Errorf("state directory: %w", e)
	}
	defer state.Close()
	lock, e := state.Lock()
	if e != nil {
		return e
	}
	defer lock.Close()
	previous := d.loadBaseline(state)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			if ctx.Err() != nil {
				return nil
			}
			s, e := d.Scan(ctx)
			if e != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("scheduled scan failed: %w", e)
			}
			raw, e := report.Render(s, "json")
			if e != nil {
				return fmt.Errorf("snapshot export failed: %w", e)
			}
			name := "scan-" + s.Started.UTC().Format("20060102T150405.000000000Z") + "-" + s.ScanID + ".json"
			if e = state.WriteSnapshot(name, raw); e != nil {
				return fmt.Errorf("snapshot persistence failed: %w", e)
			}
			removed, e := state.Prune(d.Retention)
			if e != nil {
				return fmt.Errorf("snapshot retention failed: %w", e)
			}
			if e = d.logf("snapshot %s complete=%t findings=%d diagnostics=%d\n", report.Safe(name), s.Complete, len(s.Findings), len(s.Diagnostics)); e != nil {
				return e
			}
			if e = d.logChanges(previous, s); e != nil {
				return e
			}
			for _, r := range removed {
				if e = d.logf("retention removed %s\n", report.Safe(r)); e != nil {
					return e
				}
			}
			previous = newBaseline(s)
			timer.Reset(d.Interval)
		}
	}
}

// loadBaseline restores the newest retained snapshot so change logging
// continues across restarts. Any problem is logged and the first scan then
// becomes the baseline; it never prevents scanning.
func (d Daemon) loadBaseline(state *storage.State) *baseline {
	name, raw, e := state.Latest(report.MaxInput)
	if name == "" && e == nil {
		return nil
	}
	if e == nil {
		var s domain.Snapshot
		if s, e = report.Decode(raw); e == nil {
			_ = d.logf("baseline %s findings=%d\n", report.Safe(name), len(s.Findings))
			return newBaseline(s)
		}
	}
	_ = d.logf("baseline unavailable: %s; the first scan becomes the baseline\n", report.Safe(e.Error()))
	return nil
}

// logChanges writes one line per new, resolved or changed finding and a count
// of findings whose status could not be established.
func (d Daemon) logChanges(previous *baseline, current domain.Snapshot) error {
	if previous == nil {
		return nil
	}
	drift, e := Diff(previous.snapshot, current)
	if e != nil {
		return d.logf("change comparison skipped: %s\n", report.Safe(e.Error()))
	}
	labels := map[string]string{}
	for id, label := range previous.labels {
		labels[id] = label
	}
	for _, n := range current.Graph.Nodes {
		labels[n.ID] = n.Label
	}
	for _, group := range []struct {
		status   string
		findings []domain.Finding
	}{{"new", drift.New}, {"changed", drift.Changed}, {"resolved", drift.Resolved}} {
		for _, f := range group.findings {
			subject := labels[f.Subject]
			if subject == "" {
				subject = f.Subject
			}
			if e = d.logf("finding %s severity=%s rule=%s id=%s subject=%q\n", group.status, report.Safe(f.Severity), report.Safe(f.RuleID), report.Safe(shortID(f.ID)), report.Safe(subject)); e != nil {
				return e
			}
		}
	}
	if len(drift.Unknown) > 0 {
		return d.logf("finding unknown count=%d (absent but not verified as resolved; run lasa diff on the retained snapshots for reasons)\n", len(drift.Unknown))
	}
	return nil
}

func (d Daemon) logf(format string, args ...any) error {
	if d.Log == nil {
		return nil
	}
	if _, e := fmt.Fprintf(d.Log, format, args...); e != nil {
		return fmt.Errorf("daemon log write: %w", e)
	}
	return nil
}

func shortID(id string) string {
	return strings.ToLower(id[:min(8, len(id))])
}
