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
