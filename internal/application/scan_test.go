package application

import (
	"context"
	"errors"
	"testing"

	"github.com/jasonachkar/lasa/internal/collector"
	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/domain"
)

type fake struct{ bad bool }

func (f fake) Descriptor() collector.Descriptor {
	return collector.Descriptor{ID: "fake", Version: "1"}
}
func (f fake) Collect(context.Context) domain.Batch {
	b := collector.Begin("fake", "fixture")
	if f.bad {
		b.Coverage.Inconclusive = 1
	}
	collector.Finish(&b)
	return b
}
func TestOrchestrator(t *testing.T) {
	for _, bad := range []bool{false, true} {
		engine := Engine{Host: domain.Host{ID: "host", BootID: "boot"}, Stages: []Stage{func(*domain.Snapshot) []collector.Collector { return []collector.Collector{fake{bad}} }}}
		s, e := engine.Scan(context.Background(), config.Default())
		if e != nil {
			t.Fatal(e)
		}
		if s.Complete == bad {
			t.Fatal("coverage outcome wrong")
		}
		if s.ScanID == "" || s.Schema != domain.SchemaVersion {
			t.Fatal("missing identity")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := (Engine{}).Scan(ctx, config.Default())
	if !errors.Is(e, context.Canceled) {
		t.Fatalf("%v", e)
	}
}
