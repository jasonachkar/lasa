package application

import (
	"context"
	"errors"
	"strings"
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
func TestMissingProcIsFatalAndActionable(t *testing.T) {
	c := config.Default()
	c.Proc = t.TempDir()
	_, e := Linux(c, nil)
	var d domain.Diagnostic
	if !errors.As(e, &d) || d.Code != "PROC_UNAVAILABLE" || d.Recoverable || d.Target == "" || d.Remediation == "" {
		t.Fatalf("bad prerequisite error: %v", e)
	}
}

type panickingCollector struct{}

func (panickingCollector) Descriptor() collector.Descriptor {
	return collector.Descriptor{ID: "faulting-fixture", Version: "1"}
}
func (panickingCollector) Collect(context.Context) domain.Batch { panic("PRIVATE_CONFIGURATION_VALUE") }
func TestCollectorPanicIsIsolated(t *testing.T) {
	engine := Engine{Host: domain.Host{ID: "h"}, Stages: []Stage{func(*domain.Snapshot) []collector.Collector {
		return []collector.Collector{panickingCollector{}, fake{}}
	}}}
	s, e := engine.Scan(context.Background(), config.Default())
	if e != nil {
		t.Fatal(e)
	}
	if s.Complete || len(s.Coverage) != 2 || len(s.Diagnostics) != 1 || s.Diagnostics[0].Code != "COLLECTOR_INTERNAL_ERROR" {
		t.Fatalf("panic was not isolated: %+v", s)
	}
	if strings.Contains(s.Diagnostics[0].Cause, "PRIVATE_CONFIGURATION_VALUE") {
		t.Fatal("panic payload leaked")
	}
}
