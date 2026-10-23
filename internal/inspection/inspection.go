package inspection

import (
	"context"
	"errors"
	"fmt"
	"github.com/jasonachkar/lasa/internal/access"
	linux "github.com/jasonachkar/lasa/internal/platform/linux"
	"strings"
	"time"

	"github.com/jasonachkar/lasa/internal/collector"
	"github.com/jasonachkar/lasa/internal/config"
	"github.com/jasonachkar/lasa/internal/diagnostics"
	"github.com/jasonachkar/lasa/internal/domain"
)

type Collector struct {
	Module      string
	Config      config.Config
	Snapshot    *domain.Snapshot
	Runtime     RuntimeClient
	Runner      Runner
	FS          linux.Reader
	CheckAccess func(context.Context, string, []access.Account) (access.Result, error)
}

func (c Collector) Descriptor() collector.Descriptor {
	return collector.Descriptor{ID: "inspect." + c.Module, Version: "1", Features: []string{"explicit configuration inspection", "bounded native read-only queries"}}
}

type inspection struct {
	ctx           context.Context
	c             Collector
	b             domain.Batch
	runner        Runner
	seen          map[string]bool
	items         int
	limit         int
	exhausted     bool
	evidenceBytes int
}

func (c Collector) Collect(ctx context.Context) (b domain.Batch) {
	i := &inspection{ctx: ctx, c: c, b: collector.Begin("inspect."+c.Module, "Explicit opt-in "+c.Module+" inspection in the scanner's visible system scope; no universal host or exploitability claim"), runner: c.Runner, seen: map[string]bool{}, limit: c.Config.MaxInspectionItems}
	if i.limit == 0 {
		i.limit = 256
	}
	if i.runner == nil {
		i.runner = NativeRunner{Timeout: c.Config.InspectionCommandTimeout}
	}
	defer func() { collector.Finish(&i.b); b = i.b }()
	if e := ctx.Err(); e != nil {
		i.fail("collect", c.Module, e)
		return
	}
	if c.Snapshot == nil {
		i.fail("initialize", c.Module, fmt.Errorf("snapshot is required"))
		return
	}
	switch c.Module {
	case "systemd":
		i.systemd()
	case "ssh":
		i.ssh()
	case "sudo":
		i.sudo()
	case "permissions":
		i.permissions()
	case "firewall":
		i.firewall()
	case "containers":
		i.containers()
	case "packages":
		i.packages()
	case "scheduler":
		i.scheduler()
	default:
		i.fail("initialize", c.Module, fmt.Errorf("unknown inspection module"))
	}
	return
}
func (i *inspection) next(target string) bool {
	if e := i.ctx.Err(); e != nil {
		i.fail("collect", target, e)
		return false
	}
	if i.exhausted {
		return false
	}
	if i.items >= i.limit || len(i.b.Observations) >= 25000 || i.evidenceBytes >= 8<<20 {
		i.exhausted = true
		i.b.Diagnostics = append(i.b.Diagnostics, diagnostics.Limit(i.b.Coverage.Collector, boundedDiagnostic(target)))
		i.b.Coverage.Skipped++
		return false
	}
	i.items++
	i.b.Coverage.Attempted++
	return true
}
func (i *inspection) fail(op, target string, e error) {
	d := diagnostics.New(i.b.Coverage.Collector, op, boundedDiagnostic(target), e)
	d.Cause = boundedDiagnostic(d.Cause)
	d.Remediation = "Review the named inspection's documentation, tool availability, authorized permissions and namespace scope; rerun after resolving the cause. No automatic elevation or fallback to guessed evidence is performed."
	switch {
	case errors.Is(e, context.DeadlineExceeded):
		d.Code = "INSPECTION_TIMEOUT"
		d.Remediation = "Review host load and provider availability; deliberately increase --inspection-command-timeout and --timeout if needed."
	case strings.HasPrefix(e.Error(), "RESOURCE_LIMIT:"):
		d.Code = "RESOURCE_LIMIT"
	case strings.HasPrefix(e.Error(), "NATIVE_TOOL_UNTRUSTED:"):
		d.Code = "NATIVE_TOOL_UNTRUSTED"
		d.Remediation = "Use trusted root-owned system tools in the intended host namespace; do not weaken executable trust checks or automatically elevate."
	}
	i.b.Diagnostics = append(i.b.Diagnostics, d)
	i.b.Coverage.Inconclusive++
}
func (i *inspection) unsupported(target, reason string) {
	i.b.Diagnostics = append(i.b.Diagnostics, domain.Diagnostic{Code: "INSPECTION_UNSUPPORTED", Component: i.b.Coverage.Collector, Operation: "interpret", Target: boundedDiagnostic(target), Cause: boundedDiagnostic(reason), Impact: "Affected configuration remains unknown; dependent findings cannot be confirmed or resolved.", Remediation: "Use a supported configuration/provider or inspect this target independently; retain the coverage gap.", Recoverable: true})
	i.b.Coverage.Unsupported++
}
func (i *inspection) asset(kind, label string) domain.Asset {
	if label == "" || len(label) > 4096 {
		i.unsupported("asset label", "empty or oversized inspected asset label")
		return domain.Asset{}
	}
	if len(i.b.Observations) >= 25000 || i.evidenceBytes >= 8<<20 {
		i.next(label)
		return domain.Asset{}
	}
	id := domain.Hash(i.c.Snapshot.Host.ID, i.c.Module, kind, label)
	a := domain.Asset{ID: id, StableID: id, Kind: kind, Label: label}
	if !i.seen["asset:"+id] {
		i.seen["asset:"+id] = true
		i.b.Assets = append(i.b.Assets, a)
		i.fact(a, "asset.kind", kind, label, domain.Observed)
	}
	return a
}
func (i *inspection) fact(a domain.Asset, key, value, source string, state domain.State) string {
	if a.ID == "" {
		return ""
	}
	if len(i.b.Observations) >= 25000 || i.evidenceBytes >= 8<<20 {
		i.next(source)
		return ""
	}
	if len(value) > 65536 || len(source) > 4096 || len(value)+len(source)+128 > 8<<20-i.evidenceBytes {
		i.evidenceBytes = 8 << 20
		i.next(source)
		return ""
	}
	o := domain.Fact(a.ID, key, value, source, i.b.Coverage.Collector, state, time.Now().UTC())
	if !i.seen[o.ID] {
		i.seen[o.ID] = true
		i.evidenceBytes += len(value) + len(source) + 128
		i.b.Observations = append(i.b.Observations, o)
	}
	return o.ID
}
func (i *inspection) risk(a domain.Asset, key string, value bool, state domain.State, refs ...string) {
	id := i.fact(a, key, fmt.Sprint(value), a.Label, state)
	if id == "" {
		return
	}
	filtered := refs[:0]
	known := map[string]bool{}
	for _, ref := range refs {
		if ref != "" && !known[ref] {
			filtered = append(filtered, ref)
			known[ref] = true
		}
	}
	refs = filtered
	for n := range i.b.Observations {
		if i.b.Observations[n].ID == id {
			i.b.Observations[n].Derived = true
			i.b.Observations[n].Evidence = append(i.b.Observations[n].Evidence, refs...)
			break
		}
	}
}

func boundedDiagnostic(value string) string {
	if len(value) > 4096 {
		return value[:4096] + " [truncated]"
	}
	return value
}
