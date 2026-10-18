package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jasonachkar/lasa/internal/collector"
	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/correlation"
	"github.com/jasonachkar/lasa/internal/diagnostics"
	"github.com/jasonachkar/lasa/internal/domain"
	"github.com/jasonachkar/lasa/internal/graph"
	"github.com/jasonachkar/lasa/internal/rules"
)

type Stage func(*domain.Snapshot) []collector.Collector
type Engine struct {
	Host        domain.Host
	Stages      []Stage
	Rules       []rules.Rule
	Diagnostics []domain.Diagnostic
}

func (e Engine) Scan(parent context.Context, c config.Config) (domain.Snapshot, error) {
	s := domain.Snapshot{}
	if err := c.Validate(); err != nil {
		return s, fmt.Errorf("CONFIG_INVALID: %w", err)
	}
	if err := parent.Err(); err != nil {
		return s, err
	}
	ctx, cancel := context.WithTimeout(parent, c.Timeout)
	defer cancel()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return s, fmt.Errorf("scan identity entropy: %w", err)
	}
	s = domain.Snapshot{Schema: domain.SchemaVersion, ScannerVersion: domain.Version, ScanID: hex.EncodeToString(id[:]), Started: time.Now().UTC(), Profile: c.Profile, Host: e.Host, Complete: len(e.Diagnostics) == 0, Diagnostics: append([]domain.Diagnostic(nil), e.Diagnostics...)}
	for _, stage := range e.Stages {
		collectors := stage(&s)
		if len(collectors) > 8 {
			return s, fmt.Errorf("collector stage exceeds concurrency budget of 8")
		}
		results := make(chan domain.Batch, len(collectors))
		var wg sync.WaitGroup
		for _, source := range collectors {
			wg.Add(1)
			go func(source collector.Collector) { defer wg.Done(); results <- source.Collect(ctx) }(source)
		}
		wg.Wait()
		close(results)
		var batches []domain.Batch
		for b := range results {
			batches = append(batches, b)
		}
		sort.Slice(batches, func(i, j int) bool { return batches[i].Coverage.Collector < batches[j].Coverage.Collector })
		for _, b := range batches {
			merge(&s, b)
		}
	}
	if ctx.Err() != nil {
		s.Complete = false
		s.Diagnostics = append(s.Diagnostics, diagnostics.New("scan", "collect", s.ScanID, ctx.Err()))
	}
	s.Completed = time.Now().UTC()
	for i := range s.RuntimeEvents {
		e := &s.RuntimeEvents[i]
		for _, p := range s.Processes {
			if e.BootID == s.Host.BootID && p.Namespaces["pid"] == "pid:[4026531836]" && uint32(p.PID) == e.PID && p.StartTime == e.StartBootNS/10000000 {
				e.StaticSubject = p.ID
				break
			}
		}
	}
	if _, err := graph.Build(&s); err != nil {
		return s, fmt.Errorf("GRAPH_INVALID: %w", err)
	}
	correlation.Evaluate(&s, e.Rules)
	sort.Slice(s.Diagnostics, func(i, j int) bool {
		a, b := s.Diagnostics[i], s.Diagnostics[j]
		return a.Component+a.Target+a.Operation+a.Code < b.Component+b.Target+b.Operation+b.Code
	})
	s.Sort()
	return s, nil
}
func merge(s *domain.Snapshot, b domain.Batch) {
	s.RuntimeEvents = append(s.RuntimeEvents, b.RuntimeEvents...)
	s.LostRuntimeEvents += b.LostRuntimeEvents
	s.Processes = append(s.Processes, b.Processes...)
	s.Sockets = append(s.Sockets, b.Sockets...)
	s.Interfaces = append(s.Interfaces, b.Interfaces...)
	s.Mounts = append(s.Mounts, b.Mounts...)
	s.Files = append(s.Files, b.Files...)
	s.Services = append(s.Services, b.Services...)
	s.Containers = append(s.Containers, b.Containers...)
	s.Controls = append(s.Controls, b.Controls...)
	s.Observations = append(s.Observations, b.Observations...)
	s.Diagnostics = append(s.Diagnostics, b.Diagnostics...)
	s.Coverage = append(s.Coverage, b.Coverage)
	s.Complete = s.Complete && b.Coverage.Complete
}
