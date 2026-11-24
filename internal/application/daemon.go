package application

import (
	"context"
	"fmt"
	"io"
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

func (d Daemon) Run(ctx context.Context) error {
	if d.Interval < time.Second || d.Retention < 1 || d.Retention > 10000 || d.Scan == nil {
		return fmt.Errorf("daemon requires interval >=1s, retention 1..10000 and scanner")
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
				return e
			}
			name := "scan-" + s.Started.UTC().Format("20060102T150405.000000000Z") + "-" + s.ScanID + ".json"
			if e = state.WriteSnapshot(name, raw); e != nil {
				return fmt.Errorf("snapshot persistence failed: %w", e)
			}
			if e = state.Prune(d.Retention); e != nil {
				return fmt.Errorf("snapshot retention failed: %w", e)
			}
			if d.Log != nil {
				if _, e = fmt.Fprintf(d.Log, "snapshot %s complete=%t findings=%d diagnostics=%d\n", report.Safe(name), s.Complete, len(s.Findings), len(s.Diagnostics)); e != nil {
					return fmt.Errorf("daemon log write: %w", e)
				}
			}
			timer.Reset(d.Interval)
		}
	}
}
