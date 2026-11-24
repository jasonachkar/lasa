package application

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jasonachkar/lasa/internal/domain"
)

func TestDaemonPersistsAndStops(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	d := Daemon{Directory: dir, Interval: time.Second, Retention: 2, Scan: func(context.Context) (domain.Snapshot, error) {
		calls++
		cancel()
		return domain.Snapshot{Schema: domain.SchemaVersion, ScanID: "0123456789abcdef0123456789abcdef", Host: domain.Host{ID: "h"}, Started: time.Now()}, nil
	}}
	if e := d.Run(ctx); e != nil {
		t.Fatal(e)
	}
	names, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, n := range names {
		found = found || strings.HasPrefix(n.Name(), "scan-")
	}
	if calls != 1 || !found {
		t.Fatalf("calls=%d files=%v", calls, names)
	}
}

func TestDaemonKeepsSnapshotsInTheOpenedStateDirectory(t *testing.T) {
	parent := t.TempDir()
	state := filepath.Join(parent, "state")
	original := filepath.Join(parent, "original")
	d := Daemon{Directory: state, Interval: time.Second, Retention: 2}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	d.Scan = func(context.Context) (domain.Snapshot, error) {
		if err := os.Rename(state, original); err != nil {
			return domain.Snapshot{}, err
		}
		if err := os.Mkdir(state, 0755); err != nil {
			return domain.Snapshot{}, err
		}
		stop()
		return domain.Snapshot{Schema: domain.SchemaVersion, ScanID: "0123456789abcdef0123456789abcdef", Host: domain.Host{ID: "h"}, Started: time.Now()}, nil
	}
	if err := d.Run(ctx); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(original, "scan-*.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("snapshot was not written to the originally checked directory: %v, %v", matches, err)
	}
	files, err := os.ReadDir(state)
	if err != nil || len(files) != 0 {
		t.Fatalf("replacement directory was used: %v, %v", files, err)
	}
}

// changeSnapshot returns a valid snapshot of one file that either carries a
// LASA-008 finding or records a verified negative evaluation for it.
func changeSnapshot(id string, withFinding bool) domain.Snapshot {
	s := domain.Snapshot{Schema: domain.SchemaVersion, ScanID: id, Host: domain.Host{ID: "h"}, Profile: "standard", Started: time.Now(), Complete: true,
		Graph:        domain.Graph{Nodes: []domain.Node{{ID: "file", StableID: "stable", Kind: "file", Label: "/etc/systemd/system/x.service"}}},
		Observations: []domain.Observation{{ID: "obs", Subject: "file", Key: "file.write_candidate", Value: "false", State: domain.Observed, Collector: "filesystem"}},
		Coverage:     []domain.Coverage{{Collector: "filesystem", Complete: true}},
		Evaluations:  []domain.Evaluation{{RuleID: "LASA-008", Subject: "file", State: domain.NotObserved, Evidence: []string{"obs"}}}}
	if withFinding {
		s.Observations[0].Value = "true"
		s.Evaluations[0].State = domain.Observed
		s.Findings = []domain.Finding{{ID: "ff82deeea010530250b2e7cc77664f6d", RuleID: "LASA-008", Subject: "file", StableSubject: "stable", Severity: "high", Confidence: "medium", Exposure: domain.UnknownExposure, Evidence: []string{"obs"}}}
	}
	return s
}

func TestDaemonLogsFindingChangesRetentionAndRestoresBaseline(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	run := func(scans ...domain.Snapshot) string {
		var log strings.Builder
		ctx, stop := context.WithCancel(context.Background())
		defer stop()
		i := 0
		d := Daemon{Directory: dir, Interval: time.Second, Retention: 1, Log: &log, Scan: func(context.Context) (domain.Snapshot, error) {
			s := scans[i]
			i++
			if i == len(scans) {
				stop()
			}
			return s, nil
		}}
		if e := d.Run(ctx); e != nil {
			t.Fatal(e)
		}
		return log.String()
	}
	first := run(changeSnapshot("0123456789abcdef0123456789abcde1", true), changeSnapshot("0123456789abcdef0123456789abcde2", false))
	for _, want := range []string{
		`finding resolved severity=high rule=LASA-008 id=ff82deee subject="/etc/systemd/system/x.service"`,
		"retention removed scan-",
	} {
		if !strings.Contains(first, want) {
			t.Fatalf("daemon log is missing %q:\n%s", want, first)
		}
	}
	if strings.Contains(first, "finding new") {
		t.Fatalf("the first scan has no baseline and must not report everything as new:\n%s", first)
	}
	second := run(changeSnapshot("0123456789abcdef0123456789abcde3", true))
	for _, want := range []string{"baseline scan-", "findings=0", `finding new severity=high rule=LASA-008 id=ff82deee`} {
		if !strings.Contains(second, want) {
			t.Fatalf("restarted daemon log is missing %q:\n%s", want, second)
		}
	}
}

func TestDaemonRejectsInvalidScheduleWithSpecificMessage(t *testing.T) {
	for _, tc := range []struct {
		d    Daemon
		want string
	}{
		{Daemon{Interval: 100 * time.Millisecond, Retention: 1, Scan: func(context.Context) (domain.Snapshot, error) { return domain.Snapshot{}, nil }}, "--interval"},
		{Daemon{Interval: time.Second, Retention: 0, Scan: func(context.Context) (domain.Snapshot, error) { return domain.Snapshot{}, nil }}, "--retention"},
	} {
		if e := tc.d.Run(context.Background()); e == nil || !strings.Contains(e.Error(), tc.want) {
			t.Fatalf("expected an error naming %s, got %v", tc.want, e)
		}
	}
}
