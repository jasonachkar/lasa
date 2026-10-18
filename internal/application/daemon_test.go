package application

import (
	"context"
	"os"
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
